//! "Link with OmaID": pair your own devices by typing the account number.
//!
//! Every install has a secret *account* OmaID (`account_id`, mode 0600) that is
//! never broadcast or sent anywhere. Typing it on another device runs SPAKE2
//! (P-256) against nearby devices; only a device holding the same number
//! completes the exchange, and both then trust each other's Ed25519 key as
//! "own device". A wrong guess costs the attacker one online attempt, and the
//! responder budgets those (see `RateLimiter`). Nothing derived from the
//! number appears on the wire in a form that can be attacked offline.
//!
//! The legacy `oma_id` stays what beacons and v1 flows carry; it is now only a
//! public label. Spec: PROTOCOL_V2.md, "Linking with an OmaID".

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::devicekey::{self, ct_eq, DeviceIdentity};
use crate::rendezvous::{format_oma_id, generate_raw_oma_id, hmac_sha256, normalize_oma_id, validate_oma_id};

pub const DOMAIN: &str = "omasend-link-v1";
pub const SESSION_TTL: Duration = Duration::from_secs(30);
pub const MAX_SESSIONS: usize = 32;
pub const RATE_WINDOW: Duration = Duration::from_secs(600);
pub const MAX_ATTEMPTS_PER_IP: usize = 5;
pub const MAX_ATTEMPTS_TOTAL: usize = 20;

// ------------------- account OmaID (secret) -------------------

const ACCOUNT_FILE: &str = "account_id";

/// The secret account OmaID, created on first use. Never put this on the wire.
pub fn get_or_create_account_id(state_dir: &Path) -> String {
    if let Ok(s) = crate::read_secure_file(&state_dir.join(ACCOUNT_FILE)) {
        if validate_oma_id(s.trim()) {
            return format_oma_id(s.trim());
        }
    }
    new_account_id(state_dir)
}

/// Replaces the account OmaID with a fresh random one. Devices already linked
/// stay trusted; only future links need the new number.
pub fn new_account_id(state_dir: &Path) -> String {
    let id = format_oma_id(&generate_raw_oma_id());
    if let Err(e) = crate::write_secure_file(&state_dir.join(ACCOUNT_FILE), &id) {
        eprintln!("Error writing account_id: {}", e);
    }
    id
}

/// Adopts an account OmaID typed by the user (after a successful link, or to
/// join an existing account).
pub fn set_account_id(state_dir: &Path, input: &str) -> Result<String, String> {
    if !validate_oma_id(input) {
        return Err("Invalid OmaID (16 digits, checksum mismatch)".into());
    }
    let id = format_oma_id(input);
    crate::write_secure_file(&state_dir.join(ACCOUNT_FILE), &id)?;
    Ok(id)
}

// ------------------- SPAKE2 over P-256 -------------------

/// Deterministic, nothing-up-my-sleeve generator: the first x (from
/// SHA-256(seed || be32(ctr))) that is the x-coordinate of a curve point,
/// taken with even y (SEC1 prefix 0x02).
fn hash_to_point(seed: &str) -> ProjectivePoint {
    for ctr in 0u32.. {
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(ctr.to_be_bytes());
        let mut enc = [0u8; 33];
        enc[0] = 0x02;
        enc[1..].copy_from_slice(&h.finalize());
        if let Some(p) = decode_point(&enc) {
            return p;
        }
    }
    unreachable!()
}

fn point_m() -> &'static ProjectivePoint {
    static M: OnceLock<ProjectivePoint> = OnceLock::new();
    M.get_or_init(|| hash_to_point("omasend-link-v1 M"))
}

fn point_n() -> &'static ProjectivePoint {
    static N: OnceLock<ProjectivePoint> = OnceLock::new();
    N.get_or_init(|| hash_to_point("omasend-link-v1 N"))
}

fn decode_point(bytes: &[u8]) -> Option<ProjectivePoint> {
    let ep = EncodedPoint::from_bytes(bytes).ok()?;
    let ap: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    let p = ProjectivePoint::from(ap?);
    (p != ProjectivePoint::IDENTITY).then_some(p)
}

fn encode_point(p: &ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

fn reduce(bytes: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(bytes))
}

/// w = SHA-256(DOMAIN "|w|" digits) mod n. Only the 16 digits count, so
/// "1234-5678 ..." and "12345678..." give the same w.
fn password_scalar(oma_id: &str) -> Scalar {
    let mut h = Sha256::new();
    h.update(format!("{}|w|{}", DOMAIN, normalize_oma_id(oma_id)).as_bytes());
    reduce(h.finalize().into())
}

fn random_scalar() -> Scalar {
    loop {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).expect("OS randomness unavailable");
        let s = reduce(b);
        b.zeroize();
        if s != Scalar::ZERO {
            return s;
        }
    }
}

/// Keys both sides derive once K is known.
pub struct Keys {
    pub c_a: [u8; 32],
    pub c_b: [u8; 32],
    pub box_key: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.box_key.zeroize();
    }
}

fn derive_keys(pa: &[u8], pb: &[u8], k: &ProjectivePoint, w: &Scalar) -> Result<Keys, String> {
    if *k == ProjectivePoint::IDENTITY {
        return Err("Degenerate key exchange".into());
    }
    let k_enc = encode_point(k);
    let w_bytes: [u8; 32] = w.to_bytes().into();
    let mut h = Sha256::new();
    for part in [DOMAIN.as_bytes(), pa, pb, &k_enc, &w_bytes] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    let mut tt: [u8; 32] = h.finalize().into();
    let (ke, ka) = tt.split_at(16);
    let kc_a = hmac_sha256(ka, b"omasend-link-v1 KcA");
    let kc_b = hmac_sha256(ka, b"omasend-link-v1 KcB");
    let keys = Keys {
        c_a: hmac_sha256(&kc_a, &[pa, pb].concat()),
        c_b: hmac_sha256(&kc_b, &[pb, pa].concat()),
        box_key: hmac_sha256(ke, b"omasend-link-v1 box"),
    };
    tt.zeroize();
    Ok(keys)
}

/// Initiator side (the device where the user typed the number).
pub struct Initiator {
    x: Scalar,
    w: Scalar,
    pub pa: Vec<u8>,
}

impl Initiator {
    pub fn new(oma_id: &str) -> Self {
        Self::with_scalar(oma_id, random_scalar())
    }

    fn with_scalar(oma_id: &str, x: Scalar) -> Self {
        let w = password_scalar(oma_id);
        let pa = encode_point(&(ProjectivePoint::GENERATOR * x + *point_m() * w));
        Self { x, w, pa }
    }

    /// Checks the responder's confirmation; on success returns the keys
    /// (`c_a` to send back, `box_key` for the identity boxes).
    pub fn finish(&self, pb: &[u8], c_b: &[u8]) -> Result<Keys, String> {
        let pb_pt = decode_point(pb).ok_or("Invalid responder point")?;
        let k = (pb_pt - *point_n() * self.w) * self.x;
        let keys = derive_keys(&self.pa, pb, &k, &self.w)?;
        if !ct_eq(&keys.c_b, c_b) {
            return Err("OmaID does not match".into());
        }
        Ok(keys)
    }
}

/// Responder side: one step, since it confirms first.
pub fn respond(oma_id: &str, pa: &[u8]) -> Result<(Vec<u8>, Keys), String> {
    respond_with_scalar(oma_id, pa, random_scalar())
}

fn respond_with_scalar(oma_id: &str, pa: &[u8], y: Scalar) -> Result<(Vec<u8>, Keys), String> {
    let pa_pt = decode_point(pa).ok_or("Invalid initiator point")?;
    let w = password_scalar(oma_id);
    let pb = encode_point(&(ProjectivePoint::GENERATOR * y + *point_n() * w));
    let k = (pa_pt - *point_m() * w) * y;
    let keys = derive_keys(pa, &pb, &k, &w)?;
    Ok((pb, keys))
}

// ------------------- identity boxes -------------------

fn aad(dir: &str) -> String {
    format!("{} {}", DOMAIN, dir)
}

pub fn seal(box_key: &[u8; 32], dir: &str, plain: &[u8]) -> String {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(box_key));
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).expect("OS randomness unavailable");
    let a = aad(dir);
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plain, aad: a.as_bytes() })
        .expect("AES-GCM encrypt");
    B64.encode([iv.as_slice(), &ct].concat())
}

pub fn open(box_key: &[u8; 32], dir: &str, sealed_b64: &str) -> Result<Vec<u8>, String> {
    let raw = B64.decode(sealed_b64).map_err(|_| "Invalid box encoding")?;
    if raw.len() < 12 + 16 {
        return Err("Box too short".into());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(box_key));
    let a = aad(dir);
    cipher
        .decrypt(Nonce::from_slice(&raw[..12]), Payload { msg: &raw[12..], aad: a.as_bytes() })
        .map_err(|_| "Box authentication failed".to_string())
}

/// What each side signs with its Ed25519 device key, binding it to this run.
pub fn sig_transcript(pa_b64: &str, pb_b64: &str, i_pk: &str, r_pk: Option<&str>) -> String {
    match r_pk {
        Some(r) => format!("{}|{}|{}|{}|{}", DOMAIN, pa_b64, pb_b64, i_pk, r),
        None => format!("{}|{}|{}|{}", DOMAIN, pa_b64, pb_b64, i_pk),
    }
}

/// Builds the initiator's encrypted identity box for `/link/finish`.
pub fn initiator_box(id: &DeviceIdentity, keys: &Keys, pa_b64: &str, pb_b64: &str, name: &str, quic_port: u16) -> String {
    let pk = id.public_b64();
    let body = serde_json::json!({
        "pk": pk,
        "name": name,
        "quic_port": quic_port,
        "sig": id.sign_b64(sig_transcript(pa_b64, pb_b64, &pk, None).as_bytes()),
    });
    seal(&keys.box_key, "I", body.to_string().as_bytes())
}

/// A peer key proven by a link run.
#[derive(Debug, Clone)]
pub struct LinkedPeer {
    pub pk: String,
    pub name: String,
    pub quic_port: u16,
}

fn parse_identity(plain: &[u8], transcript: impl Fn(&str) -> String) -> Result<LinkedPeer, String> {
    let v: serde_json::Value = serde_json::from_slice(plain).map_err(|_| "Malformed identity box")?;
    let pk = v["pk"].as_str().ok_or("Missing pk")?.to_string();
    let sig = v["sig"].as_str().ok_or("Missing sig")?;
    let vk = devicekey::decode_pk(&pk).ok_or("Invalid public key")?;
    if !devicekey::verify_b64(&vk, transcript(&pk).as_bytes(), sig) {
        return Err("Invalid device signature".into());
    }
    Ok(LinkedPeer {
        pk,
        name: v["name"].as_str().unwrap_or("Unknown device").chars().take(64).collect(),
        quic_port: v["quic_port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(0),
    })
}

/// Initiator: opens and verifies the responder's box.
pub fn open_responder_box(keys: &Keys, pa_b64: &str, pb_b64: &str, my_pk: &str, sealed: &str) -> Result<LinkedPeer, String> {
    let plain = open(&keys.box_key, "R", sealed)?;
    parse_identity(&plain, |r_pk| sig_transcript(pa_b64, pb_b64, my_pk, Some(r_pk)))
}

// ------------------- responder sessions + rate limit -------------------

struct Session {
    pa_b64: String,
    pb_b64: String,
    keys: Keys,
    ip: IpAddr,
    created: Instant,
}

#[derive(Default)]
pub struct Responder {
    sessions: HashMap<String, Session>,
    /// (when, ip, sid) per /link/start; a successful finish removes its entry.
    attempts: Vec<(Instant, IpAddr, String)>,
}

pub enum StartError {
    RateLimited,
    Bad(String),
}

impl Responder {
    fn prune(&mut self, now: Instant) {
        self.sessions.retain(|_, s| now.duration_since(s.created) < SESSION_TTL);
        self.attempts.retain(|(t, _, _)| now.duration_since(*t) < RATE_WINDOW);
    }

    /// Every start is one online guess, so it is counted before any work.
    pub fn start(&mut self, account_id: &str, ip: IpAddr, pa_b64: &str, now: Instant) -> Result<serde_json::Value, StartError> {
        self.prune(now);
        let per_ip = self.attempts.iter().filter(|(_, a, _)| *a == ip).count();
        if per_ip >= MAX_ATTEMPTS_PER_IP || self.attempts.len() >= MAX_ATTEMPTS_TOTAL || self.sessions.len() >= MAX_SESSIONS {
            return Err(StartError::RateLimited);
        }
        let pa = B64.decode(pa_b64).map_err(|_| StartError::Bad("Invalid pA".into()))?;
        let (pb, keys) = respond(account_id, &pa).map_err(StartError::Bad)?;
        let mut sid_bytes = [0u8; 16];
        getrandom::getrandom(&mut sid_bytes).map_err(|e| StartError::Bad(e.to_string()))?;
        let sid = hex::encode(sid_bytes);
        let pb_b64 = B64.encode(&pb);
        let out = serde_json::json!({ "sid": sid, "pB": pb_b64, "cB": B64.encode(keys.c_b) });
        self.attempts.push((now, ip, sid.clone()));
        self.sessions.insert(sid, Session { pa_b64: pa_b64.to_string(), pb_b64, keys, ip, created: now });
        Ok(out)
    }

    /// Verifies the initiator, returns its identity and our sealed reply.
    pub fn finish(
        &mut self,
        id: &DeviceIdentity,
        my_name: &str,
        my_quic_port: u16,
        ip: IpAddr,
        body: &serde_json::Value,
        now: Instant,
    ) -> Result<(LinkedPeer, serde_json::Value), String> {
        self.prune(now);
        let sid = body["sid"].as_str().ok_or("Missing sid")?;
        // Single use: a session is consumed by its first finish, right or wrong.
        let s = self.sessions.remove(sid).ok_or("Unknown or expired link session")?;
        if s.ip != ip {
            return Err("Link session belongs to another address".into());
        }
        let c_a = B64.decode(body["cA"].as_str().ok_or("Missing cA")?).map_err(|_| "Invalid cA")?;
        if !ct_eq(&s.keys.c_a, &c_a) {
            return Err("OmaID does not match".into());
        }
        let plain = open(&s.keys.box_key, "I", body["box"].as_str().ok_or("Missing box")?)?;
        let peer = parse_identity(&plain, |i_pk| sig_transcript(&s.pa_b64, &s.pb_b64, i_pk, None))?;
        let my_pk = id.public_b64();
        if peer.pk == my_pk {
            return Err("Cannot link a device to itself".into());
        }
        let reply = serde_json::json!({
            "pk": my_pk,
            "name": my_name,
            "device_id": id.device_id(),
            "quic_port": my_quic_port,
            "sig": id.sign_b64(sig_transcript(&s.pa_b64, &s.pb_b64, &peer.pk, Some(&my_pk)).as_bytes()),
        });
        let sealed = seal(&s.keys.box_key, "R", reply.to_string().as_bytes());
        // A correct number is not a guess: give the attempt back.
        self.attempts.retain(|(_, _, a)| a != sid);
        Ok((peer, serde_json::json!({ "box": sealed })))
    }
}

pub fn responder() -> &'static Mutex<Responder> {
    static R: OnceLock<Mutex<Responder>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Responder::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4539-1488-0343-6467";

    fn scalar(n: u8) -> Scalar {
        let mut b = [0u8; 32];
        b[31] = n;
        reduce(b)
    }

    fn ident(seed: u8) -> DeviceIdentity {
        DeviceIdentity::from_seed([seed; 32])
    }

    #[test]
    fn generators_are_pinned() {
        // Shared with omasend-android OmaLinkTest; changing these breaks interop.
        assert_eq!(hex::encode(encode_point(point_m())), "02bf776f8c956317d2da49785228d6fd711af8a8ee32cb7aba70fd55925d94598e");
        assert_eq!(hex::encode(encode_point(point_n())), "02eecd84e595f27077112ab183f037c87e132d36742eca41580dbfa80114b12f07");
    }

    #[test]
    fn fixed_vector() {
        let ini = Initiator::with_scalar(ID, scalar(7));
        let (pb, rk) = respond_with_scalar(ID, &ini.pa, scalar(11)).unwrap();
        let ik = ini.finish(&pb, &rk.c_b).unwrap();
        assert_eq!(ik.c_a, rk.c_a);
        assert_eq!(ik.box_key, rk.box_key);
        assert_eq!(hex::encode(password_scalar(ID).to_bytes()), "8e139c2abae6f62f14b23470a7bc2e504ab4c23e00bc9e1361044ca4554d7a06");
        assert_eq!(hex::encode(&ini.pa), "0230f5731715331f68be2bc69c91e0e3af2c416f559a571bcb6b9faa149e02cf1b");
        assert_eq!(hex::encode(&pb), "03ee51e9a4fcceb1b5a8900b4877dc7fc6d13bf10c9451c2e15a2eac27a39e9d18");
        assert_eq!(hex::encode(ik.c_a), "b2977414cbce7c32aff0226f3a19c90d80e5e5b778b461f69e60242dbdcf56b0");
        assert_eq!(hex::encode(ik.c_b), "0f52e972837c60c635948d111d5b2161d7119281d537c8bc89e6c36efdd01a44");
        assert_eq!(hex::encode(ik.box_key), "f28b858430952bdbde5c49716c49a9df60d6346e57bd7f042d2710ae5eb9b026");
    }

    #[test]
    fn formatting_does_not_matter_but_digits_do() {
        let ini = Initiator::new("4539148803436467");
        let (pb, rk) = respond(ID, &ini.pa).unwrap();
        assert!(ini.finish(&pb, &rk.c_b).is_ok());

        let ini = Initiator::new("4539-1488-0343-6475");
        let (pb, rk) = respond(ID, &ini.pa).unwrap();
        assert!(ini.finish(&pb, &rk.c_b).is_err());
    }

    #[test]
    fn rejects_invalid_points() {
        assert!(respond(ID, &[0u8; 33]).is_err());
        assert!(respond(ID, &[0x02; 5]).is_err());
        let ini = Initiator::new(ID);
        assert!(ini.finish(&[0u8; 33], &[0u8; 32]).is_err());
    }

    fn full_run(r: &mut Responder, init_id: &str, ip: IpAddr, now: Instant) -> Result<LinkedPeer, String> {
        let (me, them) = (ident(1), ident(2));
        let ini = Initiator::new(init_id);
        let pa_b64 = B64.encode(&ini.pa);
        let start = r.start(ID, ip, &pa_b64, now).map_err(|e| match e {
            StartError::RateLimited => "rate limited".to_string(),
            StartError::Bad(m) => m,
        })?;
        let pb_b64 = start["pB"].as_str().unwrap().to_string();
        let pb = B64.decode(&pb_b64).unwrap();
        let c_b = B64.decode(start["cB"].as_str().unwrap()).unwrap();
        let keys = match ini.finish(&pb, &c_b) {
            Ok(k) => k,
            Err(e) => {
                // A real initiator gives up here; the attempt stays counted.
                return Err(e);
            }
        };
        let body = serde_json::json!({
            "sid": start["sid"],
            "cA": B64.encode(keys.c_a),
            "box": initiator_box(&me, &keys, &pa_b64, &pb_b64, "laptop", 4000),
        });
        let (peer, reply) = r.finish(&them, "desk", 4001, ip, &body, now)?;
        assert_eq!(peer.pk, me.public_b64());
        assert_eq!(peer.name, "laptop");
        let back = open_responder_box(&keys, &pa_b64, &pb_b64, &me.public_b64(), reply["box"].as_str().unwrap())?;
        assert_eq!(back.pk, them.public_b64());
        Ok(back)
    }

    #[test]
    fn end_to_end_and_refund() {
        let mut r = Responder::default();
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        let now = Instant::now();
        for _ in 0..10 {
            let peer = full_run(&mut r, ID, ip, now).unwrap();
            assert_eq!(peer.name, "desk");
        }
        assert!(r.attempts.is_empty());
    }

    #[test]
    fn wrong_guesses_are_budgeted() {
        let mut r = Responder::default();
        let now = Instant::now();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        for _ in 0..MAX_ATTEMPTS_PER_IP {
            assert_eq!(full_run(&mut r, "4539-1488-0343-6475", ip, now).unwrap_err(), "OmaID does not match");
        }
        assert_eq!(full_run(&mut r, ID, ip, now).unwrap_err(), "rate limited");
        // Other addresses still have budget until the global cap.
        let other: IpAddr = "10.0.0.10".parse().unwrap();
        assert!(full_run(&mut r, ID, other, now).is_ok());
        // The window slides.
        assert!(full_run(&mut r, ID, ip, now + RATE_WINDOW).is_ok());
    }

    #[test]
    fn sessions_are_single_use_and_bound() {
        let mut r = Responder::default();
        let now = Instant::now();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let ini = Initiator::new(ID);
        let pa_b64 = B64.encode(&ini.pa);
        let start = r.start(ID, ip, &pa_b64, now).ok().unwrap();
        let pb_b64 = start["pB"].as_str().unwrap();
        let keys = ini.finish(&B64.decode(pb_b64).unwrap(), &B64.decode(start["cB"].as_str().unwrap()).unwrap()).unwrap();
        let body = serde_json::json!({
            "sid": start["sid"],
            "cA": B64.encode(keys.c_a),
            "box": initiator_box(&ident(1), &keys, &pa_b64, pb_b64, "x", 0),
        });
        let other: IpAddr = "10.0.0.10".parse().unwrap();
        assert!(r.finish(&ident(2), "d", 0, other, &body, now).is_err());
        // Consumed by the failed attempt above.
        assert!(r.finish(&ident(2), "d", 0, ip, &body, now).is_err());

        let start = r.start(ID, ip, &pa_b64, now).ok().unwrap();
        let body = serde_json::json!({ "sid": start["sid"], "cA": "", "box": "" });
        assert!(r.finish(&ident(2), "d", 0, ip, &body, now + SESSION_TTL).is_err());
    }

    #[test]
    fn signature_binds_the_run() {
        let ini = Initiator::new(ID);
        let (pb, rk) = respond(ID, &ini.pa).unwrap();
        let keys = ini.finish(&pb, &rk.c_b).unwrap();
        let pa_b64 = B64.encode(&ini.pa);
        let sealed = initiator_box(&ident(1), &keys, &pa_b64, "some-other-pB", "x", 0);
        let plain = open(&rk.box_key, "I", &sealed).unwrap();
        assert!(parse_identity(&plain, |i| sig_transcript(&pa_b64, &B64.encode(&pb), i, None)).is_err());
        // Direction is part of the AAD.
        assert!(open(&rk.box_key, "R", &sealed).is_err());
    }
}
