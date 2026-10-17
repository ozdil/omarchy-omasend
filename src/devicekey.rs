//! Phase 1: per-device Ed25519 identity, QR pairing (v2) and signed requests.
//!
//! Replaces "trust whoever claims our OmaID" with "trust only public keys that were
//! exchanged through a QR / one-time secret pairing". OmaID stays a display/grouping label.
//!
//! Wire format (shared with the Android app, see PROTOCOL_V2.md):
//!
//! Pair offer URI (shown as QR by the responder):
//!   omasend://pair?v=2&pk=<b64url R_pk>&s=<b64url secret>&h=<ip>&p=<port>&n=<urlenc name>&o=<0|1>
//!
//! Pair request (initiator -> responder), POST /api/v2/pair, JSON:
//!   { "pk": b64url(I_pk), "name": str, "mac": hex(HMAC-SHA256(secret, "omasend-pair-v2|" + R_pk + "|" + I_pk)),
//!     "sig": b64url(Ed25519_I("omasend-pair-v2|" + R_pk + "|" + I_pk + "|" + mac)) }
//! Response: { "pk": b64url(R_pk), "name": str, "sig": b64url(Ed25519_R(same transcript)) }
//!
//! Signed request headers:
//!   X-OmaSend-Pk: b64url(pk)   X-OmaSend-Ts: unix secs   X-OmaSend-Nonce: 16-byte hex
//!   X-OmaSend-Sig: b64url(Ed25519(canonical))
//! canonical = "omasend-v2\n" + METHOD + "\n" + path[?query] + "\n" + ts + "\n" + nonce + "\n" + body_tag
//! body_tag  = hex(SHA-256(body)) for JSON bodies, or "stream:<content-length>" for /api/p2p/upload.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PAIR_DOMAIN: &str = "omasend-pair-v2";
pub const SIG_DOMAIN: &str = "omasend-v2";
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
pub const PAIR_OFFER_TTL_SECS: u64 = 300;
/// Backstop only: failed attempts (from any address) after which every open offer is burned.
/// The daemon limits failures per source address first (5/min), so one LAN host can no longer
/// invalidate the user's QR code with a handful of bogus requests (M17).
pub const MAX_PAIR_FAILURES: u32 = 50;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    b
}

// ------------------------------------------------------------------ identity

pub struct DeviceIdentity {
    signing: SigningKey,
}

impl DeviceIdentity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().as_bytes())
    }

    pub fn device_id(&self) -> String {
        device_id_for_pk(self.signing.verifying_key().as_bytes())
    }

    /// Raw 32-byte seed; also the omasend-core (iroh) endpoint secret, so the QUIC endpoint id
    /// equals this device's public key.
    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.signing.sign(msg).to_bytes())
    }
}

/// Short, human-checkable id derived from the public key: XXXX-XXXX-XXXX-XXXX (hex).
pub fn device_id_for_pk(pk: &[u8]) -> String {
    let h = Sha256::digest(pk);
    let hexs = hex::encode(&h[..8]).to_uppercase();
    format!("{}-{}-{}-{}", &hexs[0..4], &hexs[4..8], &hexs[8..12], &hexs[12..16])
}

/// Loads the device key from `<state_dir>/device_ed25519.key` (32-byte seed, hex, mode 0600),
/// creating it on first run.
pub fn load_or_create_identity(state_dir: &Path) -> Result<DeviceIdentity, String> {
    let path = state_dir.join("device_ed25519.key");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let bytes = hex::decode(s.trim()).map_err(|_| "Corrupt device key".to_string())?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| "Corrupt device key length".to_string())?;
        return Ok(DeviceIdentity::from_seed(seed));
    }
    let seed = random_bytes::<32>();
    write_private(&path, &hex::encode(seed))?;
    Ok(DeviceIdentity::from_seed(seed))
}

fn write_private(path: &Path, content: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Unique temp name: the CLI and the daemon may write the same file concurrently.
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), hex::encode(random_bytes::<6>())));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("open {:?}: {}", tmp, e))?;
    let res = f
        .write_all(content.as_bytes())
        .and_then(|_| f.sync_all())
        .and_then(|_| std::fs::rename(&tmp, path))
        .map_err(|e| e.to_string());
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Exclusive lock for a read-modify-write of a state file: an in-process mutex plus an
/// flock(2) on `<file>.lock`, because the CLI (pairing, unpair) and the daemon (pair accept,
/// touch) are different processes writing the same files (M11).
struct FileLock {
    _guard: std::sync::MutexGuard<'static, ()>,
    _file: Option<std::fs::File>,
}

fn lock_file(mutex: &'static Mutex<()>, path: &Path) -> FileLock {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let guard = mutex.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.with_extension("lock"))
        .ok();
    if let Some(ref f) = file {
        // SAFETY: flock on a valid, owned descriptor; released when the file is closed.
        unsafe {
            let _ = libc::flock(f.as_raw_fd(), libc::LOCK_EX);
        }
    }
    FileLock { _guard: guard, _file: file }
}

pub fn decode_pk(pk_b64: &str) -> Option<VerifyingKey> {
    let bytes = B64.decode(pk_b64.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

pub fn verify_b64(pk: &VerifyingKey, msg: &[u8], sig_b64: &str) -> bool {
    let Ok(bytes) = B64.decode(sig_b64.trim()) else { return false };
    let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else { return false };
    pk.verify_strict(msg, &Signature::from_bytes(&arr)).is_ok()
}

// ------------------------------------------------------------------ trusted keys

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TrustedKey {
    pub pk: String,
    pub device_id: String,
    pub name: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: u16,
    /// UDP port of the peer's omasend-core (QUIC) endpoint; 0 = default (53318).
    #[serde(default)]
    pub quic_port: u16,
    /// Explicitly marked by the user as one of their own devices: enables auto-accept.
    #[serde(default)]
    pub own_device: bool,
    pub added_at: u64,
    #[serde(default)]
    pub last_seen: u64,
    /// Kind of client that paired: "" for a native app/desktop, "web" for the browser
    /// client served at /web/. A browser has no server, so it can only send.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client: String,
}

pub const CLIENT_WEB: &str = "web";

impl TrustedKey {
    /// Paired from the browser client: send-only (no HTTP server, no QUIC endpoint).
    pub fn is_web(&self) -> bool {
        self.client == CLIENT_WEB
    }
}

pub struct TrustStore {
    path: PathBuf,
}

static STORE_LOCK: Mutex<()> = Mutex::new(());

impl TrustStore {
    pub fn new(state_dir: &Path) -> Self {
        Self { path: state_dir.join("trusted_keys_v2.json") }
    }

    pub fn load(&self) -> Vec<TrustedKey> {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self, keys: &[TrustedKey]) -> Result<(), String> {
        let s = serde_json::to_string_pretty(keys).map_err(|e| e.to_string())?;
        write_private(&self.path, &s)
    }

    pub fn get(&self, pk_b64: &str) -> Option<TrustedKey> {
        self.load().into_iter().find(|k| k.pk == pk_b64)
    }

    pub fn upsert(&self, key: TrustedKey) -> Result<(), String> {
        let _g = lock_file(&STORE_LOCK, &self.path);
        let mut keys = self.load();
        if let Some(existing) = keys.iter_mut().find(|k| k.pk == key.pk) {
            *existing = key;
        } else {
            keys.push(key);
        }
        self.save(&keys)
    }

    pub fn remove(&self, pk_or_device_id: &str) -> Result<bool, String> {
        let _g = lock_file(&STORE_LOCK, &self.path);
        let mut keys = self.load();
        let before = keys.len();
        keys.retain(|k| k.pk != pk_or_device_id && k.device_id != pk_or_device_id);
        let changed = keys.len() != before;
        if changed {
            self.save(&keys)?;
        }
        Ok(changed)
    }

    /// Records the address an authenticated request came from (handles DHCP/IP changes).
    pub fn touch(&self, pk_b64: &str, ip: &str) {
        let _g = lock_file(&STORE_LOCK, &self.path);
        let mut keys = self.load();
        if let Some(k) = keys.iter_mut().find(|k| k.pk == pk_b64) {
            if !ip.is_empty() {
                k.ip = ip.to_string();
            }
            k.last_seen = now_secs();
            let _ = self.save(&keys);
        }
    }
}

// ------------------------------------------------------------------ pairing

/// Offers live in a 0600 state file because the CLI/panel that creates them and the
/// daemon that accepts them are different processes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PairOffer {
    pub secret_hex: String,
    pub own_device: bool,
    pub expires_at: u64,
    pub failures: u32,
}

static OFFER_LOCK: Mutex<()> = Mutex::new(());

fn offers_path(state_dir: &Path) -> PathBuf {
    state_dir.join("pair_offers_v2.json")
}

fn load_offers(state_dir: &Path) -> Vec<PairOffer> {
    std::fs::read_to_string(offers_path(state_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_offers(state_dir: &Path, offers: &[PairOffer]) {
    if let Ok(s) = serde_json::to_string(offers) {
        let _ = write_private(&offers_path(state_dir), &s);
    }
}

fn pair_mac(secret: &[u8], responder_pk: &str, initiator_pk: &str) -> String {
    let msg = format!("{}|{}|{}", PAIR_DOMAIN, responder_pk, initiator_pk);
    hex::encode(crate::rendezvous::hmac_sha256(secret, msg.as_bytes()))
}

fn pair_transcript(responder_pk: &str, initiator_pk: &str, mac: &str) -> String {
    format!("{}|{}|{}|{}", PAIR_DOMAIN, responder_pk, initiator_pk, mac)
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            // Byte-wise: slicing `s` here could split a multibyte character and panic.
            if let Some(v) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Creates a single-use pairing offer and returns the URI to render as a QR code.
pub fn create_pair_offer(
    identity: &DeviceIdentity,
    state_dir: &Path,
    name: &str,
    host: &str,
    port: u16,
    own_device: bool,
    quic_port: u16,
) -> String {
    let secret = random_bytes::<32>();
    let _g = lock_file(&OFFER_LOCK, &offers_path(state_dir));
    let mut offers = load_offers(state_dir);
    let now = now_secs();
    offers.retain(|o| o.expires_at > now && o.failures < MAX_PAIR_FAILURES);
    offers.push(PairOffer {
        secret_hex: hex::encode(secret),
        own_device,
        expires_at: now + PAIR_OFFER_TTL_SECS,
        failures: 0,
    });
    save_offers(state_dir, &offers);
    format!(
        "omasend://pair?v=2&pk={}&s={}&h={}&p={}&n={}&o={}&q={}",
        identity.public_b64(),
        B64.encode(secret),
        url_encode(host),
        port,
        url_encode(name),
        if own_device { 1 } else { 0 },
        quic_port
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedOffer {
    pub pk: String,
    pub secret: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub own_device: bool,
    pub quic_port: u16,
}

pub fn parse_pair_uri(uri: &str) -> Result<ParsedOffer, String> {
    let rest = uri.trim().strip_prefix("omasend://pair?").ok_or("Not an OmaSend pairing link")?;
    let mut map = HashMap::new();
    for part in rest.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    if map.get("v").map(String::as_str) != Some("2") {
        return Err("Unsupported pairing version".into());
    }
    let pk = map.get("pk").cloned().ok_or("Missing pk")?;
    decode_pk(&pk).ok_or("Invalid public key")?;
    let secret = B64.decode(map.get("s").ok_or("Missing secret")?).map_err(|_| "Invalid secret")?;
    if secret.len() != 32 {
        return Err("Invalid secret length".into());
    }
    let host = url_decode(map.get("h").ok_or("Missing host")?);
    let port = map.get("p").and_then(|p| p.parse().ok()).ok_or("Invalid port")?;
    Ok(ParsedOffer {
        pk,
        secret,
        host,
        port,
        name: omasend_core::sanitize_label(&url_decode(map.get("n").map(String::as_str).unwrap_or("")), 64),
        own_device: map.get("o").map(String::as_str) == Some("1"),
        quic_port: map.get("q").and_then(|q| q.parse().ok()).unwrap_or(0),
    })
}

/// Initiator side: build the JSON body for POST /api/v2/pair.
pub fn build_pair_request(identity: &DeviceIdentity, offer: &ParsedOffer, my_name: &str, my_quic_port: u16) -> serde_json::Value {
    let my_pk = identity.public_b64();
    let mac = pair_mac(&offer.secret, &offer.pk, &my_pk);
    let sig = identity.sign_b64(pair_transcript(&offer.pk, &my_pk, &mac).as_bytes());
    serde_json::json!({ "pk": my_pk, "name": my_name, "mac": mac, "sig": sig, "quic_port": my_quic_port })
}

/// Initiator side: verify the responder's reply against the key pinned in the QR code.
pub fn verify_pair_response(identity: &DeviceIdentity, offer: &ParsedOffer, resp: &serde_json::Value) -> Result<(), String> {
    let r_pk = resp["pk"].as_str().ok_or("Missing responder pk")?;
    if r_pk != offer.pk {
        return Err("Responder key does not match the QR code".into());
    }
    let my_pk = identity.public_b64();
    let mac = pair_mac(&offer.secret, &offer.pk, &my_pk);
    let vk = decode_pk(r_pk).ok_or("Invalid responder key")?;
    let sig = resp["sig"].as_str().ok_or("Missing responder signature")?;
    if !verify_b64(&vk, pair_transcript(&offer.pk, &my_pk, &mac).as_bytes(), sig) {
        return Err("Invalid responder signature".into());
    }
    Ok(())
}

/// Responder side: validate a pairing request against an active offer.
/// On success the offer is consumed and the response JSON plus the new TrustedKey are returned.
pub fn accept_pair_request(
    identity: &DeviceIdentity,
    state_dir: &Path,
    my_name: &str,
    body: &serde_json::Value,
    peer_ip: &str,
    my_quic_port: u16,
) -> Result<(serde_json::Value, TrustedKey), String> {
    let i_pk = body["pk"].as_str().ok_or("Missing pk")?.to_string();
    let i_name = match omasend_core::sanitize_label(body["name"].as_str().unwrap_or(""), 64) {
        n if n.is_empty() => "Unknown device".to_string(),
        n => n,
    };
    let mac = body["mac"].as_str().ok_or("Missing mac")?;
    let sig = body["sig"].as_str().ok_or("Missing sig")?;
    let vk = decode_pk(&i_pk).ok_or("Invalid public key")?;
    let r_pk = identity.public_b64();

    let _g = lock_file(&OFFER_LOCK, &offers_path(state_dir));
    let mut offers = load_offers(state_dir);
    let now = now_secs();
    offers.retain(|o| o.expires_at > now && o.failures < MAX_PAIR_FAILURES);
    let idx = offers.iter().position(|o| {
        hex::decode(&o.secret_hex)
            .map(|s| ct_eq(pair_mac(&s, &r_pk, &i_pk).as_bytes(), mac.as_bytes()))
            .unwrap_or(false)
    });
    let Some(idx) = idx else {
        // Backstop: every failed attempt counts against all live offers (see MAX_PAIR_FAILURES).
        for o in offers.iter_mut() {
            o.failures += 1;
        }
        save_offers(state_dir, &offers);
        return Err("No matching pairing offer (wrong or expired QR code)".into());
    };
    if !verify_b64(&vk, pair_transcript(&r_pk, &i_pk, mac).as_bytes(), sig) {
        offers[idx].failures += 1;
        save_offers(state_dir, &offers);
        return Err("Invalid initiator signature".into());
    }
    let offer = offers.remove(idx);
    save_offers(state_dir, &offers);
    drop(_g);

    // Only known client kinds are stored; anything else is a native client ("").
    let client = if body["client"].as_str() == Some(CLIENT_WEB) { CLIENT_WEB.to_string() } else { String::new() };
    let quic_port = if client == CLIENT_WEB {
        0
    } else {
        body["quic_port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(0)
    };
    let key = TrustedKey {
        device_id: device_id_for_pk(vk.as_bytes()),
        pk: i_pk.clone(),
        name: i_name,
        ip: peer_ip.to_string(),
        port: 0,
        quic_port,
        own_device: offer.own_device,
        added_at: now,
        last_seen: now,
        client,
    };
    let resp = serde_json::json!({
        "quic_port": my_quic_port,
        "pk": r_pk,
        "name": my_name,
        "device_id": identity.device_id(),
        "sig": identity.sign_b64(pair_transcript(&r_pk, &i_pk, mac).as_bytes()),
    });
    Ok((resp, key))
}


// ------------------------------------------------------------------ signed requests

pub fn body_tag_json(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

pub fn body_tag_stream(content_length: usize) -> String {
    format!("stream:{}", content_length)
}

pub fn canonical(method: &str, path_and_query: &str, ts: u64, nonce: &str, body_tag: &str) -> String {
    format!("{}\n{}\n{}\n{}\n{}\n{}", SIG_DOMAIN, method, path_and_query, ts, nonce, body_tag)
}

/// Header lines (each ending in CRLF) to add to an outgoing request.
pub fn auth_header_lines(identity: &DeviceIdentity, method: &str, path_and_query: &str, body_tag: &str) -> String {
    let ts = now_secs();
    let nonce = hex::encode(random_bytes::<16>());
    let sig = identity.sign_b64(canonical(method, path_and_query, ts, &nonce, body_tag).as_bytes());
    format!(
        "X-OmaSend-Pk: {}\r\nX-OmaSend-Ts: {}\r\nX-OmaSend-Nonce: {}\r\nX-OmaSend-Sig: {}\r\n",
        identity.public_b64(),
        ts,
        nonce,
        sig
    )
}

static SEEN_NONCES: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());

#[derive(Debug, PartialEq)]
pub enum AuthResult {
    /// No v2 headers at all: legacy client.
    Absent,
    /// Valid signature from a key we paired with.
    Trusted(TrustedKey),
    /// Headers present but invalid, unknown key, stale or replayed.
    Rejected(&'static str),
}

pub struct SignedHeaders<'a> {
    pub pk: Option<&'a str>,
    pub ts: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub sig: Option<&'a str>,
}

pub fn verify_request(
    store: &TrustStore,
    h: &SignedHeaders,
    method: &str,
    path_and_query: &str,
    body_tag: &str,
) -> AuthResult {
    let (Some(pk), Some(ts), Some(nonce), Some(sig)) = (h.pk, h.ts, h.nonce, h.sig) else {
        return if h.pk.is_none() && h.sig.is_none() { AuthResult::Absent } else { AuthResult::Rejected("Incomplete signature headers") };
    };
    let Ok(ts_val) = ts.trim().parse::<u64>() else { return AuthResult::Rejected("Bad timestamp") };
    let now = now_secs();
    if ts_val.abs_diff(now) > MAX_CLOCK_SKEW_SECS {
        return AuthResult::Rejected("Timestamp outside allowed window");
    }
    if nonce.len() != 32 || !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return AuthResult::Rejected("Bad nonce");
    }
    let Some(trusted) = store.get(pk.trim()) else { return AuthResult::Rejected("Unknown device key") };
    let Some(vk) = decode_pk(&trusted.pk) else { return AuthResult::Rejected("Corrupt stored key") };
    if !verify_b64(&vk, canonical(method, path_and_query, ts_val, nonce, body_tag).as_bytes(), sig) {
        return AuthResult::Rejected("Invalid signature");
    }
    let mut seen = SEEN_NONCES.lock().unwrap_or_else(|p| p.into_inner());
    seen.retain(|(_, exp)| *exp > now);
    let key = format!("{}:{}", trusted.pk, nonce);
    if seen.iter().any(|(k, _)| k == &key) {
        return AuthResult::Rejected("Replayed request");
    }
    seen.push((key, now + 2 * MAX_CLOCK_SKEW_SECS + 1));
    AuthResult::Trusted(trusted)
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("omasend-v2-{}-{}", tag, hex::encode(random_bytes::<6>())));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Cross-language test vector: the Android app must produce identical values (see
    /// app/src/test/.../ProtocolV2VectorTest.kt). Do not change without updating both.
    #[test]
    fn test_url_decode_does_not_split_multibyte_chars() {
        assert_eq!(url_decode("%aç"), "%aç");
        assert_eq!(url_decode("%ç"), "%ç");
        assert_eq!(url_decode("a%20b+c"), "a b c");
    }

    #[test]
    fn test_vectors_match_android() {
        let id = DeviceIdentity::from_seed([7u8; 32]);
        let pk = id.public_b64();
        let canon = canonical("POST", "/api/p2p/request", 1_760_000_000, "00112233445566778899aabbccddeeff", &body_tag_json(b"{}"));
        let sig = id.sign_b64(canon.as_bytes());
        let mac = pair_mac(&[9u8; 32], &pk, &pk);
        println!("VECTOR pk={}\nVECTOR device_id={}\nVECTOR body_tag={}\nVECTOR sig={}\nVECTOR mac={}", pk, id.device_id(), body_tag_json(b"{}"), sig, mac);
        // Ed25519 is deterministic: these must stay stable (same values in the Android test).
        assert_eq!(pk, "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw");
        assert_eq!(id.device_id(), "FE81-2C12-F3AB-4CE6");
        assert_eq!(body_tag_json(b"{}"), "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
        assert_eq!(sig, "eFkLAbIm3RpexYvL_-DJ6IlojDwGoLd42QJ72_kyhpn7QA_GBOcYOOLoQPw7kI2GeNO0Bl0PZG60gJZvzI9oAA");
        assert_eq!(mac, "58c09b0af9427c54894465e53a59c22480cb28449242df537932d4c659cd1fb7");
        assert!(verify_b64(&decode_pk(&pk).unwrap(), canon.as_bytes(), &sig));
    }

    #[test]
    fn test_identity_persists() {
        let d = tmpdir("id");
        let a = load_or_create_identity(&d).unwrap();
        let b = load_or_create_identity(&d).unwrap();
        assert_eq!(a.public_b64(), b.public_b64());
        let mode = std::fs::metadata(d.join("device_ed25519.key")).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(mode.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_full_pairing_and_signed_request_roundtrip() {
        let r_dir = tmpdir("r");
        let responder = DeviceIdentity::from_seed(random_bytes::<32>());
        let initiator = DeviceIdentity::from_seed(random_bytes::<32>());
        let r_store = TrustStore::new(&r_dir);

        let uri = create_pair_offer(&responder, &r_dir, "Desk & Co", "192.168.1.10", 53317, true, 53318);
        let offer = parse_pair_uri(&uri).unwrap();
        assert_eq!(offer.name, "Desk & Co");
        assert!(offer.own_device);
        assert_eq!(offer.quic_port, 53318);

        let req = build_pair_request(&initiator, &offer, "Phone", 53318);
        let (resp, key) = accept_pair_request(&responder, &r_dir, "Desk", &req, "192.168.1.20", 53318).unwrap();
        verify_pair_response(&initiator, &offer, &resp).unwrap();
        assert!(key.own_device);
        assert_eq!(key.quic_port, 53318);
        assert_eq!(resp["quic_port"], 53318);
        r_store.upsert(key).unwrap();

        // Offer is single-use.
        assert!(accept_pair_request(&responder, &r_dir, "Desk", &req, "192.168.1.20", 53318).is_err());

        // Signed request from the paired initiator is trusted.
        let body = br#"{"files":[]}"#;
        let lines = auth_header_lines(&initiator, "POST", "/api/p2p/request", &body_tag_json(body));
        let get = |name: &str| lines.lines().find_map(|l| l.strip_prefix(&format!("{}: ", name)).map(|v| v.trim().to_string()));
        let (pk, ts, nonce, sig) = (get("X-OmaSend-Pk"), get("X-OmaSend-Ts"), get("X-OmaSend-Nonce"), get("X-OmaSend-Sig"));
        let h = SignedHeaders { pk: pk.as_deref(), ts: ts.as_deref(), nonce: nonce.as_deref(), sig: sig.as_deref() };
        assert!(matches!(verify_request(&r_store, &h, "POST", "/api/p2p/request", &body_tag_json(body)), AuthResult::Trusted(_)));
        // Replay is rejected.
        assert_eq!(verify_request(&r_store, &h, "POST", "/api/p2p/request", &body_tag_json(body)), AuthResult::Rejected("Replayed request"));
        // Tampered body is rejected.
        let lines2 = auth_header_lines(&initiator, "POST", "/api/p2p/request", &body_tag_json(body));
        let get2 = |name: &str| lines2.lines().find_map(|l| l.strip_prefix(&format!("{}: ", name)).map(|v| v.trim().to_string()));
        let (pk2, ts2, n2, s2) = (get2("X-OmaSend-Pk"), get2("X-OmaSend-Ts"), get2("X-OmaSend-Nonce"), get2("X-OmaSend-Sig"));
        let h2 = SignedHeaders { pk: pk2.as_deref(), ts: ts2.as_deref(), nonce: n2.as_deref(), sig: s2.as_deref() };
        assert_eq!(verify_request(&r_store, &h2, "POST", "/api/p2p/request", &body_tag_json(b"{\"evil\":1}")), AuthResult::Rejected("Invalid signature"));
    }

    #[test]
    fn test_pairing_names_drop_deceptive_characters() {
        let r_dir = tmpdir("names");
        let responder = DeviceIdentity::from_seed(random_bytes::<32>());
        let initiator = DeviceIdentity::from_seed(random_bytes::<32>());
        // A responder name with a bidi override and a line break is cleaned on the scanning side.
        let uri = create_pair_offer(&responder, &r_dir, "Desk\u{202E}\nkoc", "192.168.1.10", 53317, false, 53318);
        let offer = parse_pair_uri(&uri).unwrap();
        assert_eq!(offer.name, "Desk koc");
        // An initiator name made only of invisible characters falls back to a neutral label.
        let mut req = build_pair_request(&initiator, &offer, "Phone", 53318);
        req["name"] = serde_json::json!("\u{200B}\u{2066}\u{3164}");
        let (_, key) = accept_pair_request(&responder, &r_dir, "Desk", &req, "192.168.1.20", 53318).unwrap();
        assert_eq!(key.name, "Unknown device");
    }

    #[test]
    fn test_web_client_pairing_is_stored_send_only_and_store_stays_compatible() {
        let r_dir = tmpdir("web");
        let responder = DeviceIdentity::from_seed(random_bytes::<32>());
        let browser = DeviceIdentity::from_seed(random_bytes::<32>());
        let uri = create_pair_offer(&responder, &r_dir, "Desk", "192.168.1.10", 53317, false, 53318);
        let offer = parse_pair_uri(&uri).unwrap();
        // What the browser sends: no quic_port, client "web".
        let mut req = build_pair_request(&browser, &offer, "Firefox on Phone", 0);
        req.as_object_mut().unwrap().remove("quic_port");
        req["client"] = serde_json::json!("web");
        let (resp, key) = accept_pair_request(&responder, &r_dir, "Desk", &req, "192.168.1.30", 53318).unwrap();
        verify_pair_response(&browser, &offer, &resp).unwrap();
        assert!(key.is_web());
        assert_eq!((key.port, key.quic_port), (0, 0));
        // A web client cannot smuggle a QUIC port in.
        let uri2 = create_pair_offer(&responder, &r_dir, "Desk", "192.168.1.10", 53317, false, 53318);
        let mut req2 = build_pair_request(&browser, &parse_pair_uri(&uri2).unwrap(), "B", 0);
        req2["quic_port"] = serde_json::json!(9999);
        req2["client"] = serde_json::json!("web");
        assert_eq!(accept_pair_request(&responder, &r_dir, "Desk", &req2, "", 0).unwrap().1.quic_port, 0);
        // Unknown client kinds are not stored.
        let uri3 = create_pair_offer(&responder, &r_dir, "Desk", "192.168.1.10", 53317, false, 53318);
        let mut req3 = build_pair_request(&browser, &parse_pair_uri(&uri3).unwrap(), "B", 0);
        req3["client"] = serde_json::json!("<script>");
        assert_eq!(accept_pair_request(&responder, &r_dir, "Desk", &req3, "", 0).unwrap().1.client, "");

        // Store round trip; native keys do not get a "client" field (old readers unaffected).
        let store = TrustStore::new(&r_dir);
        store.upsert(key.clone()).unwrap();
        let mut native = key.clone();
        native.pk = DeviceIdentity::from_seed(random_bytes::<32>()).public_b64();
        native.client = String::new();
        store.upsert(native.clone()).unwrap();
        let raw = std::fs::read_to_string(r_dir.join("trusted_keys_v2.json")).unwrap();
        assert_eq!(raw.matches("\"client\"").count(), 1, "{}", raw);
        assert_eq!(store.get(&key.pk).unwrap(), key);
        assert_eq!(store.get(&native.pk).unwrap(), native);
        // A store written before the field existed still loads.
        let old = r#"[{"pk":"x","device_id":"A","name":"n","ip":"","port":0,"quic_port":0,"own_device":false,"added_at":1,"last_seen":1}]"#;
        let parsed: Vec<TrustedKey> = serde_json::from_str(old).unwrap();
        assert!(!parsed[0].is_web());
    }

    #[test]
    fn test_pairing_rejects_wrong_secret_and_unknown_keys() {
        let r_dir = tmpdir("w");
        let responder = DeviceIdentity::from_seed(random_bytes::<32>());
        let attacker = DeviceIdentity::from_seed(random_bytes::<32>());
        let uri = create_pair_offer(&responder, &r_dir, "Desk", "10.0.0.2", 53317, false, 0);
        let mut offer = parse_pair_uri(&uri).unwrap();
        offer.secret = vec![0u8; 32]; // attacker does not know the QR secret
        let req = build_pair_request(&attacker, &offer, "Evil", 0);
        assert!(accept_pair_request(&responder, &r_dir, "Desk", &req, "10.0.0.66", 53318).is_err());
        // After MAX_PAIR_FAILURES wrong attempts the real offer is burned too.
        for _ in 0..MAX_PAIR_FAILURES {
            let _ = accept_pair_request(&responder, &r_dir, "Desk", &req, "10.0.0.66", 53318);
        }
        let real = parse_pair_uri(&uri).unwrap();
        let legit = DeviceIdentity::from_seed(random_bytes::<32>());
        assert!(accept_pair_request(&responder, &r_dir, "Desk", &build_pair_request(&legit, &real, "Phone", 0), "10.0.0.3", 53318).is_err());

        // A correctly signed request from an unpaired key is rejected.
        let store = TrustStore::new(&tmpdir("u"));
        let lines = auth_header_lines(&attacker, "POST", "/api/p2p/clipboard", "x");
        let get = |name: &str| lines.lines().find_map(|l| l.strip_prefix(&format!("{}: ", name)).map(|v| v.trim().to_string()));
        let (pk, ts, nonce, sig) = (get("X-OmaSend-Pk"), get("X-OmaSend-Ts"), get("X-OmaSend-Nonce"), get("X-OmaSend-Sig"));
        let h = SignedHeaders { pk: pk.as_deref(), ts: ts.as_deref(), nonce: nonce.as_deref(), sig: sig.as_deref() };
        assert_eq!(verify_request(&store, &h, "POST", "/api/p2p/clipboard", "x"), AuthResult::Rejected("Unknown device key"));
        // No headers at all = legacy.
        let none = SignedHeaders { pk: None, ts: None, nonce: None, sig: None };
        assert_eq!(verify_request(&store, &none, "POST", "/x", "x"), AuthResult::Absent);
    }
}
