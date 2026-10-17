//! OmaID accounts: one anonymous 16-digit number shared by all of a person's devices.
//!
//! * The number never leaves the device. Argon2id(number) gives the record's lookup id and
//!   a "join key" that hides join requests from the registry.
//! * The record holds a vault (device list, revocations, the number itself) encrypted with
//!   a random vault key, and one key box per member device: the vault key and the account
//!   signing key, sealed to that device's X25519 form of its Ed25519 device key. The number
//!   alone therefore opens nothing; a new device posts a join request and an existing
//!   device approves it once, after the user compared a 6-digit code on both screens.
//! * Every write is signed with the account key and guarded by a version (compare and
//!   swap). Removing a device rotates both keys, so it loses access.
//! * With no device left, the number can reset the account after a 24 hour wait that
//!   every remaining device can cancel.
//!
//! The registry is a small Cloudflare Worker (server/account). This module does all the
//! crypto and the protocol; hosts only provide HTTP via [`AccountHttp`] and keep the
//! returned state (secret) in their protected storage. Spec: PROTOCOL_V2.md, "Accounts".

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hmac::Mac;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::{fail, CoreError};

pub const PREFIX: &str = "omasend-account-v1";
const ARGON_M_KIB: u32 = 64 * 1024;
const ARGON_T: u32 = 3;
const MAX_DEVICES: usize = 64;
const MAX_REVOKED: usize = 256;
const CAS_RETRIES: usize = 3;
const INVITE_TTL_SECS: u64 = 10 * 60;
/// QR invites open this link; everything after '#' stays on the device (browsers never
/// send the fragment), so the number is not revealed to the web server.
pub const INVITE_BASE: &str = "https://omaid.app/j";
pub const RESET_WAIT_SECS: u64 = 24 * 3600;

// ------------------------------------------------------------------ FFI surface

/// HTTP done by the host (curl on the desktop, OkHttp on Android). `status` 0 = no network.
#[uniffi::export(with_foreign)]
pub trait AccountHttp: Send + Sync {
    fn request(&self, method: String, url: String, body: String) -> HttpReply;
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct HttpReply {
    pub status: u16,
    pub body: String,
}

/// One device of the account, as stored in the vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, uniffi::Record)]
pub struct AccountDevice {
    pub pk: String,
    pub name: String,
    /// iroh relay URL this device is reachable through ("" = LAN only).
    #[serde(default)]
    pub relay: String,
    /// "ip:port" QUIC addresses on its local network.
    #[serde(default)]
    pub addrs: Vec<String>,
    #[serde(default)]
    pub added: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct JoinRequest {
    pub rid: String,
    pub pk: String,
    pub name: String,
    /// Shown on the joining device too; the user compares them before approving.
    pub code: String,
    /// Another pending request shows the same code: approving is refused.
    pub suspicious: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountInvite {
    pub state: String,
    /// Link for the QR code: `https://omaid.app/j#n=<number>&k=<invite key>`.
    pub uri: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccountStatus {
    /// Full member: devices, approvals, removal.
    Member,
    /// Join request posted, waiting for an existing device to approve it.
    Waiting,
    /// Reset requested; becomes a member when the wait is over.
    Resetting,
    /// This device was removed, or the account no longer exists. State was cleared.
    Removed,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AccountReport {
    /// Updated secret state to persist ("" when the device left the account).
    pub state: String,
    pub status: AccountStatus,
    pub number: String,
    pub devices: Vec<AccountDevice>,
    pub revoked: Vec<String>,
    pub joins: Vec<JoinRequest>,
    /// Someone started a reset of this account with the number (members can cancel).
    pub reset_pending: bool,
    /// Join code of this device while `Waiting`.
    pub my_code: String,
    /// Seconds until a reset completes (while `Resetting`).
    pub reset_wait: u64,
}

// ------------------------------------------------------------------ number

fn luhn_checksum(digits: &[u8]) -> u8 {
    let mut sum = 0u32;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut v = d as u32;
        if i % 2 == 0 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    ((10 - (sum % 10)) % 10) as u8
}

pub fn normalize_number(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// 16 digits, Luhn-checked (catches typos before any network round trip).
#[uniffi::export]
pub fn account_number_valid(input: String) -> bool {
    let n = normalize_number(&input);
    if n.len() != 16 {
        return false;
    }
    let d: Vec<u8> = n.bytes().map(|b| b - b'0').collect();
    luhn_checksum(&d[..15]) == d[15]
}

#[uniffi::export]
pub fn account_format_number(input: String) -> String {
    let n = normalize_number(&input);
    if n.len() != 16 {
        return n;
    }
    format!("{} {} {} {}", &n[0..4], &n[4..8], &n[8..12], &n[12..16])
}

/// A fresh random number: 15 uniform digits from the OS CSPRNG plus a Luhn digit.
#[uniffi::export]
pub fn account_new_number() -> String {
    let mut digits = Vec::with_capacity(16);
    while digits.len() < 15 {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).expect("OS randomness unavailable");
        for b in buf {
            // 250 = 25 * 10: rejection keeps the digits uniform.
            if b < 250 && digits.len() < 15 {
                digits.push(b % 10);
            }
        }
    }
    let c = luhn_checksum(&digits);
    digits.push(c);
    let s: String = digits.iter().map(|d| char::from(b'0' + d)).collect();
    account_format_number(s)
}

// ------------------------------------------------------------------ key derivation

struct NumberKeys {
    lookup: String,
    join_key: [u8; 32],
}

impl Drop for NumberKeys {
    fn drop(&mut self) {
        self.join_key.zeroize();
    }
}

fn hkdf32(ikm: &[u8], info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(None, ikm)
        .expand(info.as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

/// Argon2id(number): about half a second and 64 MiB, once per number and device.
fn derive_number(number: &str) -> Result<NumberKeys, CoreError> {
    let digits = normalize_number(number);
    if !account_number_valid(digits.clone()) {
        return Err(fail("invalid account number"));
    }
    let params = argon2::Params::new(ARGON_M_KIB, ARGON_T, 1, Some(32)).map_err(|e| fail(e.to_string()))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut root = [0u8; 32];
    argon
        .hash_password_into(digits.as_bytes(), PREFIX.as_bytes(), &mut root)
        .map_err(|e| fail(e.to_string()))?;
    let keys = NumberKeys {
        lookup: hex::encode(hkdf32(&root, &format!("{} lookup", PREFIX))),
        join_key: hkdf32(&root, &format!("{} join", PREFIX)),
    };
    root.zeroize();
    Ok(keys)
}

// ------------------------------------------------------------------ primitives

fn seal(key: &[u8; 32], aad: &str, plain: &[u8]) -> String {
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).expect("OS randomness unavailable");
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plain, aad: aad.as_bytes() })
        .expect("AES-GCM encrypt");
    B64.encode([iv.as_slice(), &ct].concat())
}

fn open(key: &[u8; 32], aad: &str, sealed: &str) -> Result<Vec<u8>, CoreError> {
    let raw = B64.decode(sealed).map_err(|_| fail("bad box encoding"))?;
    if raw.len() < 12 + 16 {
        return Err(fail("box too short"));
    }
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(&raw[..12]), Payload { msg: &raw[12..], aad: aad.as_bytes() })
        .map_err(|_| fail("box authentication failed"))
}

fn device_key(seed: &[u8]) -> Result<SigningKey, CoreError> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| fail("device seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn pk_b64(k: &SigningKey) -> String {
    B64.encode(k.verifying_key().as_bytes())
}

fn decode_pk(pk: &str) -> Result<VerifyingKey, CoreError> {
    let b: [u8; 32] = B64.decode(pk).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| fail("bad public key"))?;
    VerifyingKey::from_bytes(&b).map_err(|_| fail("bad public key"))
}

/// Seals `plain` to an Ed25519 device key via its X25519 (Montgomery) form.
fn seal_to_device(pk: &str, plain: &[u8]) -> Result<String, CoreError> {
    let recipient = decode_pk(pk)?.to_montgomery();
    let mut eph = [0u8; 32];
    getrandom::getrandom(&mut eph).expect("OS randomness unavailable");
    let eph_pub = curve25519_dalek::MontgomeryPoint::mul_base_clamped(eph);
    let shared = recipient.mul_clamped(eph);
    eph.zeroize();
    let mut key = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&[eph_pub.as_bytes().as_slice(), recipient.as_bytes()].concat()), shared.as_bytes())
        .expand(format!("{} key", PREFIX).as_bytes(), &mut key)
        .expect("hkdf");
    let sealed = seal(&key, &format!("{} key", PREFIX), plain);
    key.zeroize();
    Ok(B64.encode([eph_pub.as_bytes().as_slice(), &B64.decode(sealed).expect("own encoding")].concat()))
}

fn open_as_device(me: &SigningKey, sealed: &str) -> Result<Vec<u8>, CoreError> {
    let raw = B64.decode(sealed).map_err(|_| fail("bad key box"))?;
    if raw.len() < 32 + 12 + 16 {
        return Err(fail("key box too short"));
    }
    let eph_pub = curve25519_dalek::MontgomeryPoint(raw[..32].try_into().expect("32 bytes"));
    let mut sk = me.to_scalar_bytes();
    let shared = eph_pub.mul_clamped(sk);
    sk.zeroize();
    let mine = me.verifying_key().to_montgomery();
    let mut key = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&[&raw[..32], mine.as_bytes().as_slice()].concat()), shared.as_bytes())
        .expand(format!("{} key", PREFIX).as_bytes(), &mut key)
        .expect("hkdf");
    let out = open(&key, &format!("{} key", PREFIX), &B64.encode(&raw[32..]));
    key.zeroize();
    out
}

/// Where a device's key box sits in the record. Keyed with the join key, so the registry
/// cannot tell which device keys belong to an account.
fn kid(join_key: &[u8; 32], pk: &str) -> String {
    let mut m = <hmac::Hmac<Sha256> as Mac>::new_from_slice(join_key).expect("any key length");
    m.update(format!("kid|{}", pk).as_bytes());
    hex::encode(&m.finalize().into_bytes()[..16])
}

fn invite_proof(invite_key: &[u8; 32], pk: &str) -> String {
    let mut m = <hmac::Hmac<Sha256> as Mac>::new_from_slice(invite_key).expect("any key length");
    m.update(format!("{} invite|{}", PREFIX, pk).as_bytes());
    B64.encode(m.finalize().into_bytes())
}

/// 6-digit code both screens show for a join request.
pub fn join_code(pk: &str) -> String {
    let h = Sha256::digest(format!("{} code|{}", PREFIX, pk).as_bytes());
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS randomness unavailable");
    b
}

// ------------------------------------------------------------------ state and vault

/// Secret per-device state. Hosts persist it as an opaque string in protected storage.
#[derive(Serialize, Deserialize, Clone, Default)]
struct State {
    v: u32,
    server: String,
    number: String,
    lookup: String,
    join_key: String,
    #[serde(default)]
    account_sk: String,
    #[serde(default)]
    vault_key: String,
    /// Highest vault sequence seen: an older vault is a rollback and is refused.
    #[serde(default)]
    seen_seq: u64,
    /// Our pending join request id.
    #[serde(default)]
    rid: String,
    /// Our reset key, while resetting.
    #[serde(default)]
    reset_sk: String,
    /// QR invites this device showed: a join request proving one is approved without
    /// comparing codes, because whoever scanned it stood in front of this screen.
    #[serde(default)]
    invites: Vec<Invite>,
    /// The invite key we joined with, sent along with our join request.
    #[serde(default)]
    invite_used: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Invite {
    key: String,
    expires: u64,
}

impl State {
    fn parse(s: &str) -> Result<Self, CoreError> {
        let st: State = serde_json::from_str(s).map_err(|_| fail("corrupt account state"))?;
        if st.v != 1 {
            return Err(fail("unsupported account state"));
        }
        Ok(st)
    }

    fn to_json(&self) -> String {
        serde_json::to_string(self).expect("state serializes")
    }

    fn join_key(&self) -> Result<[u8; 32], CoreError> {
        hex32(&self.join_key)
    }

    fn member_keys(&self) -> Result<(SigningKey, [u8; 32]), CoreError> {
        if self.account_sk.is_empty() || self.vault_key.is_empty() {
            return Err(fail("not a member of this account yet"));
        }
        Ok((SigningKey::from_bytes(&hex32(&self.account_sk)?), hex32(&self.vault_key)?))
    }

    fn url(&self, tail: &str) -> String {
        format!("{}/v1/account/{}{}", self.server.trim_end_matches('/'), self.lookup, tail)
    }
}

fn hex32(s: &str) -> Result<[u8; 32], CoreError> {
    hex::decode(s).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| fail("corrupt key"))
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
struct Vault {
    v: u32,
    seq: u64,
    number: String,
    devices: Vec<AccountDevice>,
    revoked: Vec<String>,
}

/// What a member's key box holds.
#[derive(Serialize, Deserialize)]
struct Grant {
    account_sk: String,
    vault_key: String,
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.account_sk.zeroize();
        self.vault_key.zeroize();
    }
}

/// The registry's view of an account, as `GET /v1/account/{id}` returns it.
#[derive(Deserialize, Default)]
struct Record {
    ver: u64,
    pk: String,
    vault: String,
    #[serde(default)]
    keys: BTreeMap<String, String>,
    #[serde(default)]
    joins: Vec<RawJoin>,
    #[serde(default)]
    reset: Option<RawReset>,
}

#[derive(Deserialize, Clone)]
struct RawJoin {
    rid: String,
    blob: String,
}

#[derive(Deserialize, Clone)]
struct RawReset {
    pk: String,
    since: u64,
}

fn vault_aad() -> String {
    format!("{} vault", PREFIX)
}

fn join_aad() -> String {
    format!("{} join", PREFIX)
}

// ------------------------------------------------------------------ registry calls

struct Client {
    http: Arc<dyn AccountHttp>,
}

enum Fetch {
    Found(Record),
    Missing,
}

impl Client {
    fn call(&self, method: &str, url: String, body: String) -> Result<HttpReply, CoreError> {
        let r = self.http.request(method.to_string(), url, body);
        if r.status == 0 {
            return Err(fail("account server unreachable"));
        }
        if r.status == 429 {
            return Err(fail("too many attempts, try again in a minute"));
        }
        Ok(r)
    }

    fn get(&self, st: &State) -> Result<Fetch, CoreError> {
        let r = self.call("GET", st.url(""), String::new())?;
        match r.status {
            200 => serde_json::from_str(&r.body).map(Fetch::Found).map_err(|_| fail("malformed account record")),
            404 => Ok(Fetch::Missing),
            s => Err(server_error(s, &r.body)),
        }
    }

    /// Signed write. Returns Ok(false) on a version conflict.
    fn signed(&self, st: &State, signer: &SigningKey, mut body: Value) -> Result<bool, CoreError> {
        body["id"] = json!(st.lookup);
        body["ts"] = json!(now());
        body["pk"] = json!(pk_b64(signer));
        let text = body.to_string();
        let sig = B64.encode(signer.sign(format!("{}|{}", PREFIX, text).as_bytes()).to_bytes());
        let r = self.call("POST", st.url(""), json!({ "body": text, "sig": sig }).to_string())?;
        match r.status {
            200 => Ok(true),
            409 => Ok(false),
            s => Err(server_error(s, &r.body)),
        }
    }
}

fn server_error(status: u16, body: &str) -> CoreError {
    let msg = serde_json::from_str::<Value>(body).ok().and_then(|v| v["error"].as_str().map(str::to_string));
    fail(format!("account server error {}: {}", status, msg.unwrap_or_default()))
}

// ------------------------------------------------------------------ operations

fn new_state(server: &str, number: &str) -> Result<State, CoreError> {
    let keys = derive_number(number)?;
    Ok(State {
        v: 1,
        server: server.trim_end_matches('/').to_string(),
        number: account_format_number(number.to_string()),
        lookup: keys.lookup.clone(),
        join_key: hex::encode(keys.join_key),
        ..Default::default()
    })
}

fn clean_device(d: &AccountDevice) -> AccountDevice {
    AccountDevice {
        pk: d.pk.clone(),
        name: d.name.chars().take(64).collect(),
        relay: if d.relay.starts_with("https://") { d.relay.chars().take(256).collect() } else { String::new() },
        addrs: d.addrs.iter().take(8).map(|a| a.chars().take(64).collect()).collect(),
        added: d.added,
    }
}

/// Builds the key boxes for every device in `vault`.
fn key_boxes(join_key: &[u8; 32], vault: &Vault, account_sk: &SigningKey, vault_key: &[u8; 32]) -> Result<BTreeMap<String, String>, CoreError> {
    let grant = Grant { account_sk: hex::encode(account_sk.to_bytes()), vault_key: hex::encode(vault_key) };
    let plain = serde_json::to_vec(&grant).expect("grant serializes");
    vault.devices.iter().map(|d| Ok((kid(join_key, &d.pk), seal_to_device(&d.pk, &plain)?))).collect()
}

fn put_body(rec_ver: u64, vault: &Vault, vault_key: &[u8; 32], keys: &BTreeMap<String, String>) -> Value {
    json!({
        "op": "put",
        "ver": rec_ver,
        "vault": seal(vault_key, &vault_aad(), &serde_json::to_vec(vault).expect("vault serializes")),
        "keys": keys,
    })
}

/// Creates a new account with this device as its only member. `number` may be empty
/// (a fresh one is generated). Fails if the number is already taken.
#[uniffi::export]
pub fn account_create(http: Arc<dyn AccountHttp>, server: String, number: String, me: AccountDevice, device_seed: Vec<u8>) -> Result<String, CoreError> {
    let number = if number.trim().is_empty() { account_new_number() } else { number };
    let mut st = new_state(&server, &number)?;
    let dev = device_key(&device_seed)?;
    let account_sk = SigningKey::from_bytes(&random32());
    let vault_key = random32();
    let mut first = clean_device(&me);
    first.pk = pk_b64(&dev);
    first.added = now();
    let vault = Vault { v: 1, seq: 1, number: st.number.clone(), devices: vec![first], revoked: vec![] };
    let keys = key_boxes(&st.join_key()?, &vault, &account_sk, &vault_key)?;
    let c = Client { http };
    if !c.signed(&st, &account_sk, put_body(0, &vault, &vault_key, &keys))? {
        return Err(fail("this number already belongs to an account; join it instead"));
    }
    st.account_sk = hex::encode(account_sk.to_bytes());
    st.vault_key = hex::encode(vault_key);
    st.seen_seq = 1;
    Ok(st.to_json())
}

/// Posts a join request for an existing account. The returned state is `Waiting` until
/// another device approves; call [`account_sync`] to pick up the approval.
#[uniffi::export]
/// `number` is either the typed number or a scanned invite link.
pub fn account_join(http: Arc<dyn AccountHttp>, server: String, number: String, me: AccountDevice, device_seed: Vec<u8>) -> Result<AccountReport, CoreError> {
    let (number, invite) = parse_invite(&number);
    let mut st = new_state(&server, &number)?;
    st.invite_used = invite.map(hex::encode).unwrap_or_default();
    let dev = device_key(&device_seed)?;
    let c = Client { http: http.clone() };
    let rec = match c.get(&st)? {
        Fetch::Found(r) => r,
        Fetch::Missing => return Err(fail("no account uses this number")),
    };
    let my_pk = pk_b64(&dev);
    // Already a member (e.g. state lost but the key box is still there).
    if rec.keys.contains_key(&kid(&st.join_key()?, &my_pk)) {
        return account_sync(http, st.to_json(), me, device_seed);
    }
    let mut req = json!({ "pk": my_pk, "name": me.name.chars().take(64).collect::<String>() });
    if !st.invite_used.is_empty() {
        req["inv"] = json!(invite_proof(&hex32(&st.invite_used)?, &my_pk));
    }
    let blob = seal(&st.join_key()?, &join_aad(), req.to_string().as_bytes());
    let r = c.call("POST", st.url("/join"), json!({ "blob": blob }).to_string())?;
    if r.status != 200 {
        return Err(server_error(r.status, &r.body));
    }
    st.rid = serde_json::from_str::<Value>(&r.body).ok().and_then(|v| v["rid"].as_str().map(str::to_string)).ok_or_else(|| fail("malformed join reply"))?;
    Ok(AccountReport {
        state: st.to_json(),
        status: AccountStatus::Waiting,
        number: st.number.clone(),
        devices: vec![],
        revoked: vec![],
        joins: vec![],
        reset_pending: rec.reset.is_some(),
        my_code: join_code(&my_pk),
        reset_wait: 0,
    })
}

/// Accepts "1234 5678 ...", or an invite link `.../j#n=<digits>&k=<key>`.
fn parse_invite(input: &str) -> (String, Option<[u8; 32]>) {
    let Some((_, frag)) = input.trim().split_once('#') else { return (input.to_string(), None) };
    let mut number = String::new();
    let mut key = None;
    for part in frag.split('&') {
        match part.split_once('=') {
            Some(("n", v)) => number = v.to_string(),
            Some(("k", v)) => key = B64.decode(v).ok().and_then(|b| b.try_into().ok()),
            _ => {}
        }
    }
    (number, key)
}

/// Creates a one-time QR invite (10 minutes). Keep syncing while it is on screen: a
/// device that scanned it is approved automatically.
#[uniffi::export]
pub fn account_invite(state: String) -> Result<AccountInvite, CoreError> {
    let mut st = State::parse(&state)?;
    st.member_keys()?;
    let key = random32();
    let t = now();
    st.invites.retain(|i| i.expires > t);
    st.invites.push(Invite { key: hex::encode(key), expires: t + INVITE_TTL_SECS });
    let uri = format!("{}#n={}&k={}", INVITE_BASE, normalize_number(&st.number), B64.encode(key));
    Ok(AccountInvite { state: st.to_json(), uri })
}

fn removed_report(st: &State) -> AccountReport {
    AccountReport {
        state: String::new(),
        status: AccountStatus::Removed,
        number: st.number.clone(),
        devices: vec![],
        revoked: vec![],
        joins: vec![],
        reset_pending: false,
        my_code: String::new(),
        reset_wait: 0,
    }
}

/// Join requests that carry a valid proof for one of our unexpired invites.
fn invited_joins(st: &State, raw: &[RawJoin], vault: &Vault) -> Vec<String> {
    let Ok(jk) = st.join_key() else { return vec![] };
    let t = now();
    raw.iter()
        .take(16)
        .filter_map(|j| {
            let v: Value = serde_json::from_slice(&open(&jk, &join_aad(), &j.blob).ok()?).ok()?;
            let pk = v["pk"].as_str()?;
            let proof = v["inv"].as_str()?;
            if vault.revoked.iter().any(|r| r == pk) {
                return None;
            }
            st.invites
                .iter()
                .filter(|i| i.expires > t)
                .filter_map(|i| hex32(&i.key).ok())
                .any(|k| crate::ct_eq_str(&invite_proof(&k, pk), proof))
                .then(|| j.rid.clone())
        })
        .collect()
}

fn decode_joins(join_key: &[u8; 32], raw: &[RawJoin], vault: &Vault) -> Vec<JoinRequest> {
    let mut out: Vec<JoinRequest> = raw
        .iter()
        .take(16)
        .filter_map(|j| {
            let v: Value = serde_json::from_slice(&open(join_key, &join_aad(), &j.blob).ok()?).ok()?;
            let pk = v["pk"].as_str()?.to_string();
            decode_pk(&pk).ok()?;
            if vault.revoked.contains(&pk) || vault.devices.iter().any(|d| d.pk == pk) {
                return None;
            }
            Some(JoinRequest {
                rid: j.rid.chars().take(64).collect(),
                code: join_code(&pk),
                pk,
                name: v["name"].as_str().unwrap_or("").chars().take(64).collect(),
                suspicious: false,
            })
        })
        .collect();
    let codes: Vec<String> = out.iter().map(|j| j.code.clone()).collect();
    for j in &mut out {
        j.suspicious = codes.iter().filter(|c| **c == j.code).count() > 1;
    }
    out
}

/// Opens the vault and checks it is not older than what we have seen.
fn open_vault(st: &State, rec: &Record, vault_key: &[u8; 32]) -> Result<Vault, CoreError> {
    let vault: Vault = serde_json::from_slice(&open(vault_key, &vault_aad(), &rec.vault)?).map_err(|_| fail("malformed vault"))?;
    if vault.v != 1 {
        return Err(fail("unsupported vault version"));
    }
    if vault.seq < st.seen_seq {
        return Err(fail("the account server returned an older version of your account"));
    }
    Ok(vault)
}

/// Refreshes the account: picks up approvals, new or removed devices, join requests, a
/// changed number and our own reachability (`me`), which is written back when it changed.
#[uniffi::export]
pub fn account_sync(http: Arc<dyn AccountHttp>, state: String, me: AccountDevice, device_seed: Vec<u8>) -> Result<AccountReport, CoreError> {
    let mut st = State::parse(&state)?;
    let dev = device_key(&device_seed)?;
    let my_pk = pk_b64(&dev);
    let c = Client { http: http.clone() };
    for _ in 0..CAS_RETRIES {
        let rec = match c.get(&st)? {
            Fetch::Found(r) => r,
            Fetch::Missing => {
                if !st.reset_sk.is_empty() {
                    return Err(fail("the account no longer exists"));
                }
                return Ok(removed_report(&st));
            }
        };
        let jk = st.join_key()?;
        if !st.reset_sk.is_empty() {
            return finish_reset(&c, st, rec, me, &dev);
        }
        let Some(boxed) = rec.keys.get(&kid(&jk, &my_pk)) else {
            if !st.rid.is_empty() && st.account_sk.is_empty() {
                // Still waiting for approval (or the request expired).
                let waiting = rec.joins.iter().any(|j| j.rid == st.rid);
                if !waiting {
                    return Err(fail("the join request expired; try again"));
                }
                return Ok(AccountReport {
                    state: st.to_json(),
                    status: AccountStatus::Waiting,
                    number: st.number.clone(),
                    devices: vec![],
                    revoked: vec![],
                    joins: vec![],
                    reset_pending: rec.reset.is_some(),
                    my_code: join_code(&my_pk),
                    reset_wait: 0,
                });
            }
            // No key box for us any more: removed from the account.
            return Ok(removed_report(&st));
        };
        let grant: Grant = serde_json::from_slice(&open_as_device(&dev, boxed)?).map_err(|_| fail("malformed key box"))?;
        let account_sk = SigningKey::from_bytes(&hex32(&grant.account_sk)?);
        let vault_key = hex32(&grant.vault_key)?;
        if pk_b64(&account_sk) != rec.pk {
            return Err(fail("account key does not match the record"));
        }
        let mut vault = open_vault(&st, &rec, &vault_key)?;
        if !vault.devices.iter().any(|d| d.pk == my_pk) {
            return Ok(removed_report(&st));
        }
        st.account_sk = grant.account_sk.clone();
        st.vault_key = grant.vault_key.clone();
        st.rid.clear();
        st.seen_seq = vault.seq;

        // Another device changed the number: move to the new record.
        if account_format_number(vault.number.clone()) != st.number && account_number_valid(vault.number.clone()) {
            let mut moved = new_state(&st.server, &vault.number)?;
            moved.account_sk = st.account_sk.clone();
            moved.vault_key = st.vault_key.clone();
            moved.seen_seq = 0;
            return account_sync(http, moved.to_json(), me, device_seed);
        }

        // Keep our own entry current (name, relay, addresses).
        let mine = vault.devices.iter_mut().find(|d| d.pk == my_pk).expect("checked above");
        let mut want = clean_device(&me);
        want.pk = my_pk.clone();
        want.added = mine.added;
        if *mine != want {
            *mine = want;
            vault.seq += 1;
            if !c.signed(&st, &account_sk, put_body(rec.ver, &vault, &vault_key, &rec.keys))? {
                continue;
            }
            st.seen_seq = vault.seq;
        }
        // Devices that scanned our QR invite are in front of us: approve them now.
        let invited = invited_joins(&st, &rec.joins, &vault);
        if !invited.is_empty() {
            let mut cur = st.to_json();
            for rid in &invited {
                cur = account_approve(http.clone(), cur, rid.clone(), device_seed.clone())?;
            }
            let mut next = State::parse(&cur)?;
            next.invites.clear();
            return account_sync(http, next.to_json(), me, device_seed);
        }
        return Ok(AccountReport {
            state: st.to_json(),
            status: AccountStatus::Member,
            number: st.number.clone(),
            joins: decode_joins(&jk, &rec.joins, &vault),
            devices: vault.devices,
            revoked: vault.revoked,
            reset_pending: rec.reset.is_some(),
            my_code: String::new(),
            reset_wait: 0,
        });
    }
    Err(fail("the account changed while saving; try again"))
}

/// Approves a join request (after the user compared the codes). The new device becomes a
/// member on its next sync.
#[uniffi::export]
pub fn account_approve(http: Arc<dyn AccountHttp>, state: String, rid: String, device_seed: Vec<u8>) -> Result<String, CoreError> {
    let mut st = State::parse(&state)?;
    let _ = device_key(&device_seed)?;
    let (account_sk, vault_key) = st.member_keys()?;
    let jk = st.join_key()?;
    let c = Client { http };
    for _ in 0..CAS_RETRIES {
        let Fetch::Found(rec) = c.get(&st)? else { return Err(fail("the account no longer exists")) };
        let mut vault = open_vault(&st, &rec, &vault_key)?;
        let joins = decode_joins(&jk, &rec.joins, &vault);
        let j = joins.iter().find(|j| j.rid == rid).ok_or_else(|| fail("that request is gone or was already handled"))?;
        if j.suspicious {
            return Err(fail("two requests show the same code; reject both and try again"));
        }
        if vault.devices.len() >= MAX_DEVICES {
            return Err(fail("too many devices on this account"));
        }
        vault.devices.push(AccountDevice { pk: j.pk.clone(), name: j.name.clone(), relay: String::new(), addrs: vec![], added: now() });
        vault.seq += 1;
        let mut keys = rec.keys.clone();
        let grant = Grant { account_sk: hex::encode(account_sk.to_bytes()), vault_key: hex::encode(vault_key) };
        keys.insert(kid(&jk, &j.pk), seal_to_device(&j.pk, &serde_json::to_vec(&grant).expect("grant serializes"))?);
        let mut body = put_body(rec.ver, &vault, &vault_key, &keys);
        body["drop_joins"] = json!([rid]);
        if c.signed(&st, &account_sk, body)? {
            st.seen_seq = vault.seq;
            return Ok(st.to_json());
        }
    }
    Err(fail("the account changed while saving; try again"))
}

/// Drops a join request without adding the device.
#[uniffi::export]
pub fn account_reject(http: Arc<dyn AccountHttp>, state: String, rid: String) -> Result<(), CoreError> {
    let st = State::parse(&state)?;
    let (account_sk, _) = st.member_keys()?;
    let c = Client { http };
    if c.signed(&st, &account_sk, json!({ "op": "drop_joins", "drop_joins": [rid] }))? {
        Ok(())
    } else {
        Err(fail("could not reject the request"))
    }
}

/// Re-keys the account without `drop` (removed devices) and, optionally, under a new
/// number. Old keys stop working, so a removed device cannot read or write any more.
fn rekey(c: &Client, st: &mut State, drop: Option<&str>, new_number: Option<&str>) -> Result<(), CoreError> {
    let (account_sk, vault_key) = st.member_keys()?;
    for _ in 0..CAS_RETRIES {
        let Fetch::Found(rec) = c.get(st)? else { return Err(fail("the account no longer exists")) };
        let mut vault = open_vault(st, &rec, &vault_key)?;
        if let Some(pk) = drop {
            vault.devices.retain(|d| d.pk != pk);
            if !vault.revoked.iter().any(|r| r == pk) {
                vault.revoked.push(pk.to_string());
            }
            let excess = vault.revoked.len().saturating_sub(MAX_REVOKED);
            vault.revoked.drain(..excess);
        }
        let new_sk = SigningKey::from_bytes(&random32());
        let new_vk = random32();
        if let Some(n) = new_number {
            let mut target = new_state(&st.server, n)?;
            let mut nv = vault.clone();
            nv.number = target.number.clone();
            nv.seq = 1;
            let keys = key_boxes(&target.join_key()?, &nv, &new_sk, &new_vk)?;
            if !c.signed(&target, &new_sk, put_body(0, &nv, &new_vk, &keys))? {
                return Err(fail("that number is already taken"));
            }
            // The old record keeps pointing members at the new number until they move.
            vault.number = target.number.clone();
            vault.seq += 1;
            target.account_sk = hex::encode(new_sk.to_bytes());
            target.vault_key = hex::encode(new_vk);
            target.seen_seq = 1;
            let keys = key_boxes(&st.join_key()?, &vault, &account_sk, &vault_key)?;
            if !c.signed(st, &account_sk, put_body(rec.ver, &vault, &vault_key, &keys))? {
                continue;
            }
            *st = target;
            return Ok(());
        }
        vault.seq += 1;
        let keys = key_boxes(&st.join_key()?, &vault, &new_sk, &new_vk)?;
        let mut body = put_body(rec.ver, &vault, &new_vk, &keys);
        body["new_pk"] = json!(pk_b64(&new_sk));
        if c.signed(st, &account_sk, body)? {
            st.account_sk = hex::encode(new_sk.to_bytes());
            st.vault_key = hex::encode(new_vk);
            st.seen_seq = vault.seq;
            return Ok(());
        }
    }
    Err(fail("the account changed while saving; try again"))
}

/// Removes a device from the account and rotates the account keys.
#[uniffi::export]
pub fn account_remove(http: Arc<dyn AccountHttp>, state: String, pk: String) -> Result<String, CoreError> {
    let mut st = State::parse(&state)?;
    rekey(&Client { http }, &mut st, Some(&pk), None)?;
    Ok(st.to_json())
}

/// Moves the account to a fresh number (e.g. the old one leaked). Other devices follow on
/// their next sync; nothing has to be typed again.
#[uniffi::export]
pub fn account_change_number(http: Arc<dyn AccountHttp>, state: String) -> Result<String, CoreError> {
    let mut st = State::parse(&state)?;
    let n = account_new_number();
    rekey(&Client { http }, &mut st, None, Some(&n))?;
    Ok(st.to_json())
}

/// Leaves the account: removes this device everywhere. The state should be deleted after.
#[uniffi::export]
pub fn account_leave(http: Arc<dyn AccountHttp>, state: String, device_seed: Vec<u8>) -> Result<(), CoreError> {
    let mut st = State::parse(&state)?;
    let pk = pk_b64(&device_key(&device_seed)?);
    rekey(&Client { http }, &mut st, Some(&pk), None)
}

/// Deletes the whole account from the registry (the last device leaving).
#[uniffi::export]
pub fn account_delete(http: Arc<dyn AccountHttp>, state: String) -> Result<(), CoreError> {
    let st = State::parse(&state)?;
    let (account_sk, _) = st.member_keys()?;
    let c = Client { http };
    if c.signed(&st, &account_sk, json!({ "op": "delete" }))? {
        Ok(())
    } else {
        Err(fail("could not delete the account"))
    }
}

/// With no device left to approve: claims the account with the number alone. Every
/// device still on the account sees `reset_pending` and can cancel during the wait.
#[uniffi::export]
pub fn account_reset_start(http: Arc<dyn AccountHttp>, server: String, number: String) -> Result<String, CoreError> {
    let mut st = new_state(&server, &number)?;
    let reset_sk = SigningKey::from_bytes(&random32());
    let c = Client { http };
    if !c.signed(&st, &reset_sk, json!({ "op": "reset" }))? {
        return Err(fail("a reset is already in progress for this account"));
    }
    st.reset_sk = hex::encode(reset_sk.to_bytes());
    Ok(st.to_json())
}

/// Cancels someone else's reset of our account (a member device).
#[uniffi::export]
pub fn account_cancel_reset(http: Arc<dyn AccountHttp>, state: String) -> Result<(), CoreError> {
    let st = State::parse(&state)?;
    let (account_sk, _) = st.member_keys()?;
    let c = Client { http };
    if c.signed(&st, &account_sk, json!({ "op": "cancel_reset" }))? {
        Ok(())
    } else {
        Err(fail("could not cancel the reset"))
    }
}

fn finish_reset(c: &Client, mut st: State, rec: Record, me: AccountDevice, dev: &SigningKey) -> Result<AccountReport, CoreError> {
    let reset_sk = SigningKey::from_bytes(&hex32(&st.reset_sk)?);
    let waiting = |left: u64| AccountReport {
        state: st.to_json(),
        status: AccountStatus::Resetting,
        number: st.number.clone(),
        devices: vec![],
        revoked: vec![],
        joins: vec![],
        reset_pending: true,
        my_code: String::new(),
        reset_wait: left,
    };
    let Some(reset) = rec.reset.clone().filter(|r| r.pk == pk_b64(&reset_sk)) else {
        return Err(fail("the reset was cancelled by one of the account's devices"));
    };
    let elapsed = now().saturating_sub(reset.since);
    if elapsed < RESET_WAIT_SECS {
        return Ok(waiting(RESET_WAIT_SECS - elapsed));
    }
    // Take over: a fresh vault with only this device, signed by the reset key.
    let account_sk = SigningKey::from_bytes(&random32());
    let vault_key = random32();
    let mut first = clean_device(&me);
    first.pk = pk_b64(dev);
    first.added = now();
    let vault = Vault { v: 1, seq: 1, number: st.number.clone(), devices: vec![first], revoked: vec![] };
    let keys = key_boxes(&st.join_key()?, &vault, &account_sk, &vault_key)?;
    let mut body = put_body(rec.ver, &vault, &vault_key, &keys);
    body["op"] = json!("reset_finish");
    body["new_pk"] = json!(pk_b64(&account_sk));
    if !c.signed(&st, &reset_sk, body)? {
        return Err(fail("the account changed during the reset; try again"));
    }
    st.reset_sk.zeroize();
    st.reset_sk.clear();
    st.account_sk = hex::encode(account_sk.to_bytes());
    st.vault_key = hex::encode(vault_key);
    st.seen_seq = 1;
    Ok(AccountReport {
        state: st.to_json(),
        status: AccountStatus::Member,
        number: st.number.clone(),
        devices: vault.devices.clone(),
        revoked: vec![],
        joins: vec![],
        reset_pending: false,
        my_code: String::new(),
        reset_wait: 0,
    })
}

/// Verifies a registry write (used by tests and mirrored by the Worker).
pub fn verify_write(pk: &str, body: &str, sig: &str) -> bool {
    let Ok(vk) = decode_pk(pk) else { return false };
    let Some(sig) = B64.decode(sig).ok().and_then(|b| <[u8; 64]>::try_from(b).ok()) else { return false };
    vk.verify(format!("{}|{}", PREFIX, body).as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig)).is_ok()
}

#[cfg(test)]
mod tests;
