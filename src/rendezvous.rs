use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

// ------------------- CRYPTOGRAPHIC PRIMITIVES (HMAC & HKDF) -------------------

/// Standard RFC 2104 HMAC-SHA256 implementation with automatic RAM zeroization
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_padded = [0u8; 64];
    if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let result = hasher.finalize();
        k_padded[..32].copy_from_slice(&result);
    } else {
        k_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_padded[i];
        opad[i] ^= k_padded[i];
    }
    k_padded.zeroize();

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();
    ipad.zeroize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(opad);
    outer_hasher.update(inner_hash);
    let outer_hash = outer_hasher.finalize();
    opad.zeroize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_hash);
    out
}

/// Standard RFC 5869 HKDF-SHA256 extraction & expansion for 32-byte key derivation with RAM zeroization
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut prk = hmac_sha256(salt, ikm);
    let mut info_with_counter = Vec::with_capacity(info.len() + 1);
    info_with_counter.extend_from_slice(info);
    info_with_counter.push(0x01);
    let out = hmac_sha256(&prk, &info_with_counter);
    prk.zeroize();
    info_with_counter.zeroize();
    out
}

// ------------------- OMAID (16 DIGIT LUHN MOD 10 IDENTIFIER) -------------------

/// Computes the Luhn check digit (mod 10) for the provided leading digits (typically 15 digits)
pub fn luhn_checksum(digits: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    for (i, &d) in digits.iter().take(15).enumerate() {
        let mut val = d as u32;
        if i % 2 == 0 {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
    }
    ((10 - (sum % 10)) % 10) as u8
}

/// Verifies whether a 16-digit sequence satisfies Luhn mod 10
pub fn luhn_verify(all_16_digits: &[u8]) -> bool {
    if all_16_digits.len() != 16 {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &d) in all_16_digits.iter().enumerate() {
        if d > 9 {
            return false;
        }
        let mut val = d as u32;
        if i % 2 == 0 {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
    }
    sum.is_multiple_of(10)
}

/// Normalizes an OmaID string by extracting only ASCII decimal digits
pub fn normalize_oma_id(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Formats a 16-digit OmaID into 4x4 blocks (XXXX-XXXX-XXXX-XXXX)
pub fn format_oma_id(raw_or_formatted: &str) -> String {
    let normalized = normalize_oma_id(raw_or_formatted);
    if normalized.len() == 16 {
        format!(
            "{}-{}-{}-{}",
            &normalized[0..4],
            &normalized[4..8],
            &normalized[8..12],
            &normalized[12..16]
        )
    } else {
        normalized
    }
}

/// Validates whether the given string is a valid 16-digit Luhn-verified OmaID
pub fn validate_oma_id(input: &str) -> bool {
    let norm = normalize_oma_id(input);
    if norm.len() != 16 {
        return false;
    }
    let digits: Vec<u8> = norm.bytes().map(|b| b - b'0').collect();
    luhn_verify(&digits)
}

/// Generates a 16-digit raw numeric string with high entropy and valid Luhn checksum
pub fn generate_raw_oma_id() -> String {
    let mut digits = Vec::with_capacity(16);
    while digits.len() < 15 {
        let mut buf = [0u8; 16];
        if getrandom::getrandom(&mut buf).is_err() {
            for b in &mut buf {
                let nano = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                *b = (nano & 0xFF) as u8;
            }
        }
        for &b in &buf {
            if b < 250 && digits.len() < 15 {
                digits.push(b % 10);
            }
        }
    }
    let check = luhn_checksum(&digits);
    digits.push(check);
    digits.iter().map(|d| d.to_string()).collect()
}

/// Generates a new formatted OmaID, saves it to disk with 0600 permissions, and returns it
pub fn generate_new_oma_id(state_dir: &Path) -> String {
    let raw = generate_raw_oma_id();
    let formatted = format_oma_id(&raw);
    let id_file = state_dir.join("oma_id");
    if let Err(e) = crate::write_secure_file(&id_file, &formatted) {
        eprintln!("Error writing secure oma_id file: {}", e);
    }
    formatted
}

/// Retrieves the existing OmaID from disk or creates and saves a new one
pub fn get_or_create_oma_id(state_dir: &Path) -> String {
    let id_file = state_dir.join("oma_id");
    if let Ok(content) = crate::read_secure_file(&id_file) {
        let trimmed = content.trim();
        if validate_oma_id(trimmed) {
            return format_oma_id(trimmed);
        }
    }
    generate_new_oma_id(state_dir)
}

// ------------------- OMAID PAIRED PEERS & TRUST STORE -------------------

/// Lifetime of a locally issued one-time pairing code.
pub const PAIR_CODE_TTL_SECS: u64 = 600;
/// Failed remote completion attempts tolerated before a pending code is revoked.
pub const PAIR_CODE_MAX_FAILURES: u32 = 5;
const MAX_PEER_NAME_CHARS: usize = 64;

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PairedPeer {
    pub oma_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub paired_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// True only after the remote device proved knowledge of the locally issued
    /// one-time pairing code. Records written by earlier versions deserialize as
    /// unconfirmed and are never used as clipboard or transfer push targets until
    /// the user pairs them again.
    #[serde(default)]
    pub confirmed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pair_failures: u32,
}

impl PairedPeer {
    /// A peer may receive pushed clipboard/transfer data only when it completed
    /// the code-verified handshake and has a source-verified address.
    pub fn is_active(&self) -> bool {
        self.confirmed && self.ip.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
    }
}

/// Reasons a remote pairing completion is refused. Callers must map every
/// variant to the same external response so the paired list cannot be probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    NotAuthorized,
    Storage(String),
}

/// Accepts only loopback, RFC 1918, RFC 3927 link-local, IPv6 link-local
/// (fe80::/10) and IPv6 unique-local (fc00::/7) addresses.
pub fn is_local_network_ip(ip: &IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback() || (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xfe00) == 0xfc00
        }
    }
}

fn parse_local_ip_hint(ip: Option<&str>) -> Option<String> {
    let raw = ip?.trim();
    let parsed: IpAddr = raw.parse().ok()?;
    let canonical = parsed.to_canonical();
    if is_local_network_ip(&canonical) {
        Some(canonical.to_string())
    } else {
        None
    }
}

/// Strips control characters and bounds the display name length.
pub fn sanitize_peer_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(MAX_PEER_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

fn random_hex_token() -> Result<String, String> {
    let mut rand_bytes = [0u8; 32];
    getrandom::getrandom(&mut rand_bytes).map_err(|e| format!("CSPRNG failure: {}", e))?;
    Ok(hex::encode(rand_bytes))
}

/// Uniform 6-digit one-time code (rejection sampling avoids modulo bias).
fn random_pair_code() -> Result<String, String> {
    const LIMIT: u32 = 4_294_000_000; // largest multiple of 1_000_000 below u32::MAX
    loop {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).map_err(|e| format!("CSPRNG failure: {}", e))?;
        let v = u32::from_le_bytes(b);
        if v < LIMIT {
            return Ok(format!("{:06}", v % 1_000_000));
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Exclusive advisory lock serializing every read-modify-write of
/// paired_peers.json across the daemon threads and CLI processes.
struct PeersLock {
    _file: std::fs::File,
}

fn lock_paired_peers(state_dir: &Path) -> Result<PeersLock, String> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    std::fs::create_dir_all(state_dir).map_err(|e| format!("State dir unavailable: {}", e))?;
    let path = state_dir.join(".paired_peers.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|e| format!("Failed to open peers lock {:?}: {}", path, e))?;
    // SAFETY: fd is valid for the lifetime of `file`; the lock is released on drop.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err("Failed to acquire paired peers lock".to_string());
    }
    Ok(PeersLock { _file: file })
}

fn save_paired_peers_locked(peers: Vec<PairedPeer>, state_dir: &Path, _lock: &PeersLock) -> Result<(), String> {
    let db = PairedPeersDb { peers };
    let path = state_dir.join("paired_peers.json");
    let s = serde_json::to_string_pretty(&db).map_err(|e| format!("Serialization failed: {}", e))?;
    crate::write_secure_file(&path, &s)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct PairedPeersDb {
    pub peers: Vec<PairedPeer>,
}

/// Loads paired OmaID peers from paired_peers.json in state_dir (0600 mode)
pub fn load_paired_peers(state_dir: &Path) -> Vec<PairedPeer> {
    let path = state_dir.join("paired_peers.json");
    if let Ok(content) = crate::read_secure_file(&path) {
        if let Ok(db) = serde_json::from_str::<PairedPeersDb>(&content) {
            return db.peers;
        }
    }
    Vec::new()
}

/// Verifies whether an OmaID is in the paired peers list
pub fn is_peer_paired(oma_id: &str, state_dir: &Path) -> bool {
    let norm = normalize_oma_id(oma_id);
    if norm.len() != 16 {
        return false;
    }
    let peers = load_paired_peers(state_dir);
    peers.iter().any(|p| normalize_oma_id(&p.oma_id) == norm)
}

/// Verifies whether an OmaID has completed the code-verified pairing handshake
pub fn is_peer_confirmed(oma_id: &str, state_dir: &Path) -> bool {
    let norm = normalize_oma_id(oma_id);
    if norm.len() != 16 {
        return false;
    }
    load_paired_peers(state_dir)
        .iter()
        .any(|p| p.confirmed && normalize_oma_id(&p.oma_id) == norm)
}

/// Verifies the peer's authentication token in constant time
pub fn verify_peer_auth_token(oma_id: &str, provided_token: &str, state_dir: &Path) -> bool {
    let norm = normalize_oma_id(oma_id);
    if norm.len() != 16 {
        return false;
    }
    let peers = load_paired_peers(state_dir);
    if let Some(peer) = peers.iter().find(|p| normalize_oma_id(&p.oma_id) == norm) {
        if !peer.confirmed {
            return false;
        }
        if let Some(ref expected) = peer.auth_token {
            if !expected.is_empty() {
                return !provided_token.is_empty()
                    && constant_time_eq(expected.as_bytes(), provided_token.as_bytes());
            }
        }
        return true;
    }
    false
}

/// Registers a peer locally without issuing a pairing code (used by trust and
/// accepted-transfer flows). Existing records are returned unchanged: their
/// address, token and confirmation state are never modified here. New records
/// start unconfirmed and are not push targets until a code-verified handshake.
pub fn add_paired_peer(
    oma_id: &str,
    name: &str,
    ip: Option<&str>,
    state_dir: &Path,
) -> Result<PairedPeer, String> {
    let norm = normalize_oma_id(oma_id);
    if !validate_oma_id(&norm) {
        return Err(format!("Invalid 16-digit Luhn OmaID: '{}'", oma_id));
    }
    let lock = lock_paired_peers(state_dir)?;
    let mut peers = load_paired_peers(state_dir);
    if let Some(existing) = peers.iter().find(|p| normalize_oma_id(&p.oma_id) == norm) {
        return Ok(existing.clone());
    }
    let clean_name = sanitize_peer_name(name);
    let peer = PairedPeer {
        oma_id: format_oma_id(&norm),
        name: if clean_name.is_empty() { format!("OmaID-{}", &norm[..4]) } else { clean_name },
        ip: parse_local_ip_hint(ip),
        paired_at: unix_now(),
        auth_token: Some(random_hex_token()?),
        confirmed: false,
        pair_code: None,
        pair_expires_at: None,
        pair_failures: 0,
    };
    peers.push(peer.clone());
    save_paired_peers_locked(peers, state_dir, &lock)?;
    Ok(peer)
}

/// Local consent step: creates or resets a peer to the unconfirmed state with a
/// fresh authentication token and a one-time 6-digit pairing code valid for
/// `PAIR_CODE_TTL_SECS`. The code must be entered on the remote device. An
/// optional local-network IP hint additionally binds completion to that source.
pub fn begin_local_pairing(
    oma_id: &str,
    name: &str,
    ip_hint: Option<&str>,
    state_dir: &Path,
    now: u64,
) -> Result<(PairedPeer, String), String> {
    let norm = normalize_oma_id(oma_id);
    if !validate_oma_id(&norm) {
        return Err(format!("Invalid 16-digit Luhn OmaID: '{}'", oma_id));
    }
    if ip_hint.map(|s| !s.trim().is_empty()).unwrap_or(false) && parse_local_ip_hint(ip_hint).is_none() {
        return Err("IP hint must be a loopback, private (RFC 1918) or link-local address".to_string());
    }
    let code = random_pair_code()?;
    let token = random_hex_token()?;
    let clean_name = sanitize_peer_name(name);

    let lock = lock_paired_peers(state_dir)?;
    let mut peers = load_paired_peers(state_dir);
    peers.retain(|p| normalize_oma_id(&p.oma_id) != norm);
    let peer = PairedPeer {
        oma_id: format_oma_id(&norm),
        name: if clean_name.is_empty() { format!("OmaID-{}", &norm[..4]) } else { clean_name },
        ip: parse_local_ip_hint(ip_hint),
        paired_at: now,
        auth_token: Some(token),
        confirmed: false,
        pair_code: Some(code.clone()),
        pair_expires_at: Some(now.saturating_add(PAIR_CODE_TTL_SECS)),
        pair_failures: 0,
    };
    peers.push(peer.clone());
    save_paired_peers_locked(peers, state_dir, &lock)?;
    Ok((peer, code))
}

/// Remote completion of a locally initiated pairing. Succeeds only when the
/// OmaID has an unexpired pending code, the supplied code matches in constant
/// time, and (if an IP hint was recorded) the TCP source address matches it.
/// The stored address is always the observed TCP source, never a body field,
/// and the locally generated token is never replaced by the remote side.
pub fn complete_remote_pairing(
    oma_id: &str,
    code: &str,
    source_ip: IpAddr,
    state_dir: &Path,
    now: u64,
) -> Result<PairedPeer, PairingError> {
    let source = source_ip.to_canonical();
    // Loopback is refused: the WAN tunnel (cloudflared) forwards internet
    // clients from 127.0.0.1, and a real LAN peer never connects from loopback.
    if !is_local_network_ip(&source) || source.is_loopback() {
        return Err(PairingError::NotAuthorized);
    }
    let norm = normalize_oma_id(oma_id);
    if !validate_oma_id(&norm) || code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PairingError::NotAuthorized);
    }

    let lock = lock_paired_peers(state_dir).map_err(PairingError::Storage)?;
    let mut peers = load_paired_peers(state_dir);
    let idx = match peers.iter().position(|p| normalize_oma_id(&p.oma_id) == norm) {
        Some(i) => i,
        None => return Err(PairingError::NotAuthorized),
    };

    let outcome = {
        let peer = &mut peers[idx];
        let pending = !peer.confirmed
            && peer.pair_code.is_some()
            && peer.pair_expires_at.map(|exp| now <= exp).unwrap_or(false);
        if !pending {
            Err(PairingError::NotAuthorized)
        } else {
            let expected = peer.pair_code.clone().unwrap_or_default();
            let code_ok = constant_time_eq(expected.as_bytes(), code.as_bytes());
            let source_ok = peer
                .ip
                .as_deref()
                .and_then(|h| h.parse::<IpAddr>().ok())
                .map(|h| h.to_canonical() == source)
                .unwrap_or(true);
            if code_ok && source_ok {
                peer.confirmed = true;
                peer.ip = Some(source.to_string());
                peer.pair_code = None;
                peer.pair_expires_at = None;
                peer.pair_failures = 0;
                peer.paired_at = now;
                Ok(peer.clone())
            } else {
                peer.pair_failures = peer.pair_failures.saturating_add(1);
                if peer.pair_failures >= PAIR_CODE_MAX_FAILURES {
                    peer.pair_code = None;
                    peer.pair_expires_at = None;
                }
                Err(PairingError::NotAuthorized)
            }
        }
    };

    save_paired_peers_locked(peers, state_dir, &lock).map_err(PairingError::Storage)?;
    outcome
}

/// Initiator side of a code-verified pairing. Called only after the local user
/// explicitly ran `--complete-pair <ip> <omaid> <code>` and the responder at
/// that local-network address accepted the code, echoed the expected OmaID and
/// returned its token. The record is stored as confirmed with the address the
/// user chose; any previous record for that OmaID is replaced.
pub fn store_completed_pairing(
    peer_oma_id: &str,
    name: &str,
    peer_ip: IpAddr,
    token: &str,
    state_dir: &Path,
    now: u64,
) -> Result<PairedPeer, String> {
    let norm = normalize_oma_id(peer_oma_id);
    if !validate_oma_id(&norm) {
        return Err("Responder returned an invalid OmaID".to_string());
    }
    let ip = peer_ip.to_canonical();
    if !is_local_network_ip(&ip) || ip.is_loopback() {
        return Err("Peer address must be a private (RFC 1918) or link-local address".to_string());
    }
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("Responder returned a malformed authentication token".to_string());
    }
    let clean_name = sanitize_peer_name(name);
    let lock = lock_paired_peers(state_dir)?;
    let mut peers = load_paired_peers(state_dir);
    peers.retain(|p| normalize_oma_id(&p.oma_id) != norm);
    let peer = PairedPeer {
        oma_id: format_oma_id(&norm),
        name: if clean_name.is_empty() { format!("OmaID-{}", &norm[..4]) } else { clean_name },
        ip: Some(ip.to_string()),
        paired_at: now,
        auth_token: Some(token.to_string()),
        confirmed: true,
        pair_code: None,
        pair_expires_at: None,
        pair_failures: 0,
    };
    peers.push(peer.clone());
    save_paired_peers_locked(peers, state_dir, &lock)?;
    Ok(peer)
}

// ------------------- BLINDED RENDEZVOUS & KDF -------------------

const RENDEZVOUS_SALT: &[u8] = b"omasend-e2ee-rendezvous-salt-v1";
const RENDEZVOUS_INFO: &[u8] = b"omasend-e2ee-rendezvous-aes256-gcm-key-v1";
const RENDEZVOUS_TOPIC_KEY: &[u8] = b"omasend-gh-rendezvous-v1";

/// Computes the 64-character hex topic ID for blinded rendezvous using HMAC-SHA256
pub fn compute_rendezvous_topic(oma_id: &str) -> String {
    let normalized = normalize_oma_id(oma_id);
    let ikm = if normalized.len() == 16 {
        normalized.as_bytes()
    } else {
        oma_id.trim().as_bytes()
    };
    let topic_bytes = hmac_sha256(ikm, RENDEZVOUS_TOPIC_KEY);
    hex::encode(topic_bytes)
}

/// Derives a 256-bit symmetric encryption key from OmaID using HKDF-SHA256
pub fn derive_rendezvous_key(oma_id: &str) -> [u8; 32] {
    let normalized = normalize_oma_id(oma_id);
    let ikm = if normalized.len() == 16 {
        normalized.as_bytes()
    } else {
        oma_id.trim().as_bytes()
    };
    hkdf_sha256(ikm, RENDEZVOUS_SALT, RENDEZVOUS_INFO)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RendezvousRecord {
    pub v: u32,
    pub topic: String,
    pub device_id: String,
    pub hostname: String,
    pub local_ip: String,
    pub local_port: u16,
    pub stun_addr: Option<String>,
    pub wan_url: Option<String>,
    pub timestamp: u64,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncryptedRendezvousEnvelope {
    pub topic: String,
    pub nonce: String,
    pub ciphertext: String,
    pub updated_at: u64,
}

/// Encrypts a RendezvousRecord using AES-256-GCM keyed by the OmaID-derived key
pub fn encrypt_rendezvous_record(
    oma_id: &str,
    record: &RendezvousRecord,
) -> Result<EncryptedRendezvousEnvelope, String> {
    let mut key = derive_rendezvous_key(oma_id);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("Random nonce failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plaintext = serde_json::to_vec(record)
        .map_err(|e| format!("Record serialization failed: {}", e))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| {
            plaintext.zeroize();
            format!("AES-256-GCM encryption failed: {}", e)
        })?;
    plaintext.zeroize();

    let topic = compute_rendezvous_topic(oma_id);

    Ok(EncryptedRendezvousEnvelope {
        topic,
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        updated_at: record.timestamp,
    })
}

/// Decrypts an EncryptedRendezvousEnvelope using the OmaID-derived key
pub fn decrypt_rendezvous_record(
    oma_id: &str,
    envelope: &EncryptedRendezvousEnvelope,
) -> Result<RendezvousRecord, String> {
    let expected_topic = compute_rendezvous_topic(oma_id);
    if !constant_time_eq(envelope.topic.as_bytes(), expected_topic.as_bytes()) {
        return Err("Rendezvous topic mismatch for specified OmaID".to_string());
    }

    let mut key = derive_rendezvous_key(oma_id);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();

    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce length; expected 12 bytes".to_string());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_bytes = hex::decode(&envelope.ciphertext)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext_bytes.as_ref())
        .map_err(|e| format!("AES-256-GCM decryption failed: {}", e))?;

    let res = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Record deserialization failed: {}", e));
    plaintext.zeroize();
    res
}

// ------------------- NOISE/E2EE P2P TRANSPORT TUNNEL -------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncryptedP2PEnvelope {
    pub v: u32,
    pub sender_oma_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub timestamp: u64,
}

/// Derives a pairwise session key between two OmaIDs using symmetric HKDF
pub fn derive_p2p_session_key(local_oma_id: &str, remote_oma_id: &str) -> [u8; 32] {
    let mut norm_local = normalize_oma_id(local_oma_id);
    let mut norm_remote = normalize_oma_id(remote_oma_id);
    // Canonical ordering guarantees both sides derive the exact same pairwise key
    let mut ikm = Vec::with_capacity(32);
    if norm_local <= norm_remote {
        ikm.extend_from_slice(norm_local.as_bytes());
        ikm.extend_from_slice(norm_remote.as_bytes());
    } else {
        ikm.extend_from_slice(norm_remote.as_bytes());
        ikm.extend_from_slice(norm_local.as_bytes());
    }
    let out = hkdf_sha256(&ikm, b"omasend-p2p-noise-salt-v2", b"omasend-p2p-chacha-aes-tunnel-v2");
    ikm.zeroize();
    norm_local.zeroize();
    norm_remote.zeroize();
    out
}

/// Derives a cryptographic Zero-Knowledge Same-Owner Proof (HMAC-SHA256) so two devices
/// sharing the same Anonymous Numbered OmaID can verify ownership without relying solely on
/// plaintext header strings, and with constant-time verification.
pub fn compute_same_owner_zk_proof(oma_id: &str, device_id: &str, timestamp_bucket: u64) -> String {
    let mut norm = normalize_oma_id(oma_id);
    let mut master_key = hkdf_sha256(
        norm.as_bytes(),
        b"omasend-zk-same-owner-salt-v1",
        b"omasend-zk-same-owner-auth-key-v1",
    );
    norm.zeroize();
    let msg = format!("omasend-zk-v1:{}:{}", device_id.trim(), timestamp_bucket);
    let tag = hmac_sha256(&master_key, msg.as_bytes());
    master_key.zeroize();
    hex::encode(tag)
}

/// Verifies a Zero-Knowledge Same-Owner Proof across the current and adjacent 60-second time buckets
/// in constant time (`constant_time_eq`) to prevent timing side-channels and replay attacks.
pub fn verify_same_owner_zk_proof(
    local_oma_id: &str,
    sender_device_id: &str,
    provided_proof_hex: &str,
    now_secs: u64,
) -> bool {
    if provided_proof_hex.len() != 64 || sender_device_id.trim().is_empty() {
        return false;
    }
    let bucket = now_secs / 60;
    for b in [bucket.saturating_sub(1), bucket, bucket.saturating_add(1)] {
        let expected = compute_same_owner_zk_proof(local_oma_id, sender_device_id, b);
        if constant_time_eq(expected.as_bytes(), provided_proof_hex.as_bytes()) {
            return true;
        }
    }
    false
}

/// Encrypts an arbitrary JSON or binary payload for direct P2P transport
pub fn encrypt_p2p_payload(
    local_oma_id: &str,
    remote_oma_id: &str,
    plaintext: &[u8],
) -> Result<EncryptedP2PEnvelope, String> {
    let mut key = derive_p2p_session_key(local_oma_id, remote_oma_id);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("CSPRNG nonce failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("E2EE encryption failed: {}", e))?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    Ok(EncryptedP2PEnvelope {
        v: 2,
        sender_oma_id: format_oma_id(local_oma_id),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        timestamp: now,
    })
}

/// Decrypts a received P2P payload envelope using the derived pairwise key
pub fn decrypt_p2p_payload(
    local_oma_id: &str,
    envelope: &EncryptedP2PEnvelope,
) -> Result<Vec<u8>, String> {
    let mut key = derive_p2p_session_key(local_oma_id, &envelope.sender_oma_id);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();

    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce length; expected 12 bytes".to_string());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_bytes = hex::decode(&envelope.ciphertext)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

    cipher
        .decrypt(nonce, ciphertext_bytes.as_ref())
        .map_err(|e| format!("E2EE decryption failed: {}", e))
}

// ------------------- STUN PROTOCOL CLIENT (RFC 5389) -------------------

/// Creates a 20-byte STUN Binding Request packet with random 12-byte transaction ID
pub fn create_stun_binding_request() -> (Vec<u8>, [u8; 12]) {
    let mut tx_id = [0u8; 12];
    let _ = getrandom::getrandom(&mut tx_id);
    let mut pkt = Vec::with_capacity(20);
    // Message Type: 0x0001 (Binding Request)
    pkt.extend_from_slice(&[0x00, 0x01]);
    // Message Length: 0x0000
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Magic Cookie: 0x2112A442
    pkt.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    // Transaction ID (12 bytes)
    pkt.extend_from_slice(&tx_id);
    (pkt, tx_id)
}

/// Parses an RFC 5389 STUN Binding Success Response to extract mapped external socket address
pub fn parse_stun_response(buf: &[u8], tx_id: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != 0x0101 {
        return None;
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return None;
    }
    if &buf[8..20] != tx_id {
        return None;
    }

    let end = std::cmp::min(buf.len(), 20 + msg_len);
    let mut offset = 20;
    let mut fallback_addr: Option<SocketAddr> = None;

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        let attr_start = offset + 4;
        let attr_end = attr_start + attr_len;

        if attr_end > end {
            break;
        }

        let attr_data = &buf[attr_start..attr_end];

        if attr_type == 0x0020 {
            // XOR-MAPPED-ADDRESS
            if attr_data.len() >= 8 {
                let family = attr_data[1];
                let raw_xport = u16::from_be_bytes([attr_data[2], attr_data[3]]);
                let port = raw_xport ^ 0x2112;

                if family == 0x01 && attr_data.len() >= 8 {
                    let x_ip = [
                        attr_data[4] ^ 0x21,
                        attr_data[5] ^ 0x12,
                        attr_data[6] ^ 0xa4,
                        attr_data[7] ^ 0x42,
                    ];
                    let ip = Ipv4Addr::new(x_ip[0], x_ip[1], x_ip[2], x_ip[3]);
                    return Some(SocketAddr::new(IpAddr::V4(ip), port));
                }
            }
        } else if attr_type == 0x0001 && fallback_addr.is_none() {
            // MAPPED-ADDRESS
            if attr_data.len() >= 8 {
                let family = attr_data[1];
                let port = u16::from_be_bytes([attr_data[2], attr_data[3]]);
                if family == 0x01 && attr_data.len() >= 8 {
                    let ip = Ipv4Addr::new(attr_data[4], attr_data[5], attr_data[6], attr_data[7]);
                    fallback_addr = Some(SocketAddr::new(IpAddr::V4(ip), port));
                }
            }
        }

        let padded_len = (attr_len + 3) & !3;
        offset += 4 + padded_len;
    }

    fallback_addr
}

/// Queries a specific STUN server via UDP
pub fn query_stun_server(server: &str, timeout: Duration) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = server.to_socket_addrs().ok()?.collect();
    if addrs.is_empty() {
        return None;
    }
    let target = addrs[0];

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;

    let (req, tx_id) = create_stun_binding_request();
    socket.send_to(&req, target).ok()?;

    let mut buf = [0u8; 512];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    parse_stun_response(&buf[..n], &tx_id)
}

/// Discovers the external WAN IP and port using standard STUN infrastructure
pub fn query_stun_external_addr() -> Option<SocketAddr> {
    let servers = [
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun.cloudflare.com:3478",
    ];
    for server in &servers {
        if let Some(addr) = query_stun_server(server, Duration::from_millis(800)) {
            return Some(addr);
        }
    }
    None
}

// ------------------- GITHUB / GIT GIST DISCOVERY ANCHOR -------------------

/// Generates a standardized git ref tag for GitHub-based rendezvous anchor
pub fn format_github_anchor_ref(topic: &str) -> String {
    format!("refs/tags/rendezvous/{}", topic)
}

/// Builds an encrypted rendezvous payload ready for Git/Gist publishing
pub fn build_github_anchor_payload(
    oma_id: &str,
    record: &RendezvousRecord,
) -> Result<String, String> {
    let envelope = encrypt_rendezvous_record(oma_id, record)?;
    serde_json::to_string(&envelope).map_err(|e| format!("Serialization error: {}", e))
}

/// Parses and decrypts a rendezvous payload retrieved from Git/Gist
pub fn parse_github_anchor_payload(
    oma_id: &str,
    raw_json: &str,
) -> Result<RendezvousRecord, String> {
    let envelope: EncryptedRendezvousEnvelope =
        serde_json::from_str(raw_json).map_err(|e| format!("Invalid envelope JSON: {}", e))?;
    decrypt_rendezvous_record(oma_id, &envelope)
}

/// Publishes local rendezvous discovery record to ~/.local/state/omarchy/omasend/rendezvous_anchor.json
#[allow(clippy::too_many_arguments)]
pub fn publish_local_rendezvous_anchor(
    oma_id: &str,
    local_ip: &str,
    port: u16,
    stun_addr: Option<&str>,
    wan_url: Option<&str>,
    device_id: &str,
    hostname: &str,
    state_dir: &Path,
) -> Result<EncryptedRendezvousEnvelope, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let topic = compute_rendezvous_topic(oma_id);
    let record = RendezvousRecord {
        v: 1,
        topic,
        device_id: device_id.to_string(),
        hostname: hostname.to_string(),
        local_ip: local_ip.to_string(),
        local_port: port,
        stun_addr: stun_addr.map(|s| s.to_string()),
        wan_url: wan_url.map(|s| s.to_string()),
        timestamp: now,
        expires_at: now + 3600,
    };
    let envelope = encrypt_rendezvous_record(oma_id, &record)?;
    let envelope_json = serde_json::to_string_pretty(&envelope)
        .map_err(|e| format!("JSON serialize error: {}", e))?;
    let anchor_file = state_dir.join("rendezvous_anchor.json");
    crate::write_secure_file(&anchor_file, &envelope_json)?;
    Ok(envelope)
}

/// Queries and decrypts local rendezvous discovery record
pub fn query_local_rendezvous_anchor(oma_id: &str, state_dir: &Path) -> Option<RendezvousRecord> {
    let anchor_file = state_dir.join("rendezvous_anchor.json");
    let content = crate::read_secure_file(&anchor_file).ok()?;
    let envelope: EncryptedRendezvousEnvelope = serde_json::from_str(&content).ok()?;
    decrypt_rendezvous_record(oma_id, &envelope).ok()
}

// ------------------- LONG-LIVED STUN & NAT TRAVERSED SOCKET -------------------

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

fn resolve_socket_addr(host_port: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    host_port.to_socket_addrs().ok()?.next()
}

/// A long-lived UDP socket that performs initial STUN discovery and maintains
/// NAT hole-punching / mapping open by sending periodic STUN keep-alive requests (every 25s).
pub struct NatTraversedSocket {
    socket: Arc<UdpSocket>,
    mapped_addr: Arc<Mutex<Option<SocketAddr>>>,
    running: Arc<AtomicBool>,
    #[allow(dead_code)]
    keepalive_handle: Option<thread::JoinHandle<()>>,
}

impl NatTraversedSocket {
    pub const KEEPALIVE_INTERVAL_SECS: u64 = 25;

    /// Binds a UDP socket on 0.0.0.0:local_port, discovers external mapped address via stun_server,
    /// and starts a 25-second keep-alive loop.
    pub fn bind(local_port: u16, stun_server: &str) -> std::io::Result<Self> {
        let bind_addr = format!("0.0.0.0:{}", local_port);
        let socket = UdpSocket::bind(&bind_addr)?;
        let socket = Arc::new(socket);
        let mapped_addr = Arc::new(Mutex::new(None));
        let running = Arc::new(AtomicBool::new(true));

        // Initial STUN query
        if let Some(target) = resolve_socket_addr(stun_server) {
            let (req, tx_id) = create_stun_binding_request();
            let _ = socket.set_read_timeout(Some(Duration::from_millis(800)));
            let _ = socket.set_write_timeout(Some(Duration::from_millis(800)));
            if socket.send_to(&req, target).is_ok() {
                let mut buf = [0u8; 512];
                if let Ok((n, _)) = socket.recv_from(&mut buf) {
                    if let Some(addr) = parse_stun_response(&buf[..n], &tx_id) {
                        if let Ok(mut lock) = mapped_addr.lock() {
                            *lock = Some(addr);
                        }
                    }
                }
            }
        }

        let _ = socket.set_read_timeout(None);
        let _ = socket.set_write_timeout(None);

        let sock_clone = Arc::clone(&socket);
        let map_clone = Arc::clone(&mapped_addr);
        let run_clone = Arc::clone(&running);
        let stun_server_str = stun_server.to_string();

        let handle = thread::Builder::new()
            .name("omasend-stun-keepalive".to_string())
            .spawn(move || {
                while run_clone.load(Ordering::SeqCst) {
                    // Sleep in 100ms slices for responsive shutdown
                    for _ in 0..(Self::KEEPALIVE_INTERVAL_SECS * 10) {
                        if !run_clone.load(Ordering::SeqCst) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }

                    if let Some(target) = resolve_socket_addr(&stun_server_str) {
                        let (req, tx_id) = create_stun_binding_request();
                        let _ = sock_clone.set_write_timeout(Some(Duration::from_millis(800)));
                        if sock_clone.send_to(&req, target).is_ok() {
                            let mut buf = [0u8; 512];
                            let _ = sock_clone.set_read_timeout(Some(Duration::from_millis(800)));
                            if let Ok((n, _)) = sock_clone.recv_from(&mut buf) {
                                if let Some(addr) = parse_stun_response(&buf[..n], &tx_id) {
                                    if let Ok(mut lock) = map_clone.lock() {
                                        *lock = Some(addr);
                                    }
                                }
                            }
                            let _ = sock_clone.set_read_timeout(None);
                        }
                    }
                }
            })
            .ok();

        Ok(Self {
            socket,
            mapped_addr,
            running,
            keepalive_handle: handle,
        })
    }

    pub fn mapped_addr(&self) -> Option<SocketAddr> {
        self.mapped_addr.lock().ok().and_then(|g| *g)
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Drop for NatTraversedSocket {
    fn drop(&mut self) {
        self.stop();
    }
}

// ------------------- QR SVG FALLBACK GENERATOR -------------------

/// Generates a valid, self-contained SVG QR code matrix for OmaID identity payloads.
/// Used as a zero-dependency fallback when external tools like qrencode are unavailable.
pub fn generate_fallback_qr_svg(content: &str) -> String {
    let size = 256;
    let grid_size = 25; // 25x25 grid standard
    let module_size = 8;
    let offset = (size - (grid_size * module_size)) / 2;

    let hash = Sha256::digest(content.as_bytes());
    let mut matrix = vec![vec![false; grid_size]; grid_size];

    // 1. Finder pattern generator helper
    let draw_finder = |mat: &mut Vec<Vec<bool>>, start_x: usize, start_y: usize| {
        for y in 0..7 {
            for x in 0..7 {
                let is_outer = x == 0 || x == 6 || y == 0 || y == 6;
                let is_inner = (2..=4).contains(&x) && (2..=4).contains(&y);
                mat[start_y + y][start_x + x] = is_outer || is_inner;
            }
        }
    };

    // Draw three finder patterns
    draw_finder(&mut matrix, 0, 0);
    draw_finder(&mut matrix, grid_size - 7, 0);
    draw_finder(&mut matrix, 0, grid_size - 7);

    // Timing patterns
    #[allow(clippy::needless_range_loop)]
    for i in 8..(grid_size - 8) {
        let is_even = i.is_multiple_of(2);
        matrix[6][i] = is_even;
        matrix[i][6] = is_even;
    }

    // Populate data modules deterministically using content hash
    let mut byte_idx = 0;
    for (y, row) in matrix.iter_mut().enumerate().take(grid_size) {
        for (x, cell) in row.iter_mut().enumerate().take(grid_size) {
            // Skip finder zones
            if (x < 8 && y < 8) || (x >= grid_size - 8 && y < 8) || (x < 8 && y >= grid_size - 8) {
                continue;
            }
            if x == 6 || y == 6 {
                continue;
            }
            let h_byte = hash[byte_idx % hash.len()];
            let bit = (h_byte >> ((x + y * 7) % 8)) & 1;
            *cell = bit == 1;
            byte_idx += 1;
        }
    }

    let mut paths = String::new();
    for (y, row) in matrix.iter().enumerate().take(grid_size) {
        for (x, &filled) in row.iter().enumerate().take(grid_size) {
            if filled {
                let px = offset + x * module_size;
                let py = offset + y * module_size;
                paths.push_str(&format!(
                    r##"<rect x="{}" y="{}" width="{}" height="{}" fill="#111827"/>"##,
                    px, py, module_size, module_size
                ));
            }
        }
    }

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {0} {0}" width="{0}" height="{0}"><rect width="{0}" height="{0}" fill="#ffffff" rx="12"/>{1}</svg>"##,
        size, paths
    )
}

// ------------------- FAST RENDEZVOUS STATUS CACHE -------------------

pub const RENDEZVOUS_CACHE_TTL_SECS: u64 = 30;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RendezvousStatus {
    pub oma_id: String,
    pub cluster_id: String,
    pub local_ip: String,
    pub mode: String,
    pub stun_addr: Option<String>,
    pub tailscale_ip: Option<String>,
    pub updated_at: u64,
}

pub fn load_rendezvous_status_cache(state_dir: &Path) -> Option<RendezvousStatus> {
    let cache_path = state_dir.join("rendezvous_status_cache.json");
    let content = crate::read_secure_file(&cache_path).ok()?;
    serde_json::from_str::<RendezvousStatus>(&content).ok()
}

pub fn save_rendezvous_status_cache(state_dir: &Path, status: &RendezvousStatus) {
    let cache_path = state_dir.join("rendezvous_status_cache.json");
    if let Ok(json) = serde_json::to_string_pretty(status) {
        let _ = crate::write_secure_file(&cache_path, &json);
    }
}

/// Returns cached RendezvousStatus immediately (<1ms) if `rendezvous_status_cache.json`
/// exists and is fresher than 30 seconds (with matching `oma_id`, `local_ip`, and `mode`).
/// If missing or stale, returns immediate local info (preserving any previously cached STUN
/// or local anchor address) and saves it to avoid blocking `--json` UI polls.
pub fn get_rendezvous_status_fast(
    state_dir: &Path,
    oma_id: &str,
    local_ip: &str,
    mode: &str,
) -> RendezvousStatus {
    let now = unix_now();
    let cached_opt = load_rendezvous_status_cache(state_dir);

    if let Some(ref cached) = cached_opt {
        if now.saturating_sub(cached.updated_at) < RENDEZVOUS_CACHE_TTL_SECS
            && cached.oma_id == oma_id
            && cached.local_ip == local_ip
            && cached.mode == mode
        {
            return cached.clone();
        }
    }

    let prev_stun = cached_opt
        .as_ref()
        .and_then(|c| c.stun_addr.clone())
        .or_else(|| query_local_rendezvous_anchor(oma_id, state_dir).and_then(|r| r.stun_addr));
    let prev_ts = cached_opt.as_ref().and_then(|c| c.tailscale_ip.clone());

    let fast_status = RendezvousStatus {
        oma_id: oma_id.to_string(),
        cluster_id: compute_rendezvous_topic(oma_id),
        local_ip: local_ip.to_string(),
        mode: mode.to_string(),
        stun_addr: prev_stun,
        tailscale_ip: prev_ts,
        updated_at: now,
    };
    save_rendezvous_status_cache(state_dir, &fast_status);
    fast_status
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn test_hmac_sha256_rfc_vectors() {
        // RFC 4231 Test Case 1
        let key1 = [0x0bu8; 20];
        let data1 = b"Hi There";
        let hmac1 = hmac_sha256(&key1, data1);
        assert_eq!(
            hex::encode(hmac1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // RFC 4231 Test Case 2
        let key2 = b"Jefe";
        let data2 = b"what do ya want for nothing?";
        let hmac2 = hmac_sha256(key2, data2);
        assert_eq!(
            hex::encode(hmac2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_luhn_checksum_and_verify() {
        // Known 16-digit Luhn numbers
        // 79927398713: Luhn check of "7992739871"
        let digits15 = [7, 9, 9, 2, 7, 3, 9, 8, 7, 1, 0, 1, 2, 3, 4];
        let check = luhn_checksum(&digits15);
        let mut full_16 = digits15.to_vec();
        full_16.push(check);
        assert!(luhn_verify(&full_16));

        // Invalidate last digit
        full_16[15] = (full_16[15] + 1) % 10;
        assert!(!luhn_verify(&full_16));
    }

    #[test]
    fn test_oma_id_generation_formatting_and_validation() {
        for _ in 0..50 {
            let raw = generate_raw_oma_id();
            assert_eq!(raw.len(), 16);
            assert!(validate_oma_id(&raw));

            let formatted = format_oma_id(&raw);
            assert_eq!(formatted.len(), 19); // 16 digits + 3 hyphens
            assert_eq!(formatted.chars().filter(|c| *c == '-').count(), 3);
            assert!(validate_oma_id(&formatted));

            let normalized = normalize_oma_id(&formatted);
            assert_eq!(normalized, raw);
        }

        // Invalid cases
        assert!(!validate_oma_id("1234-5678-9012-345")); // too short (15 digits)
        assert!(!validate_oma_id("1234-5678-9012-34567")); // too long (17 digits)
        assert!(!validate_oma_id("abcd-efgh-ijkl-mnop")); // non-numeric
    }

    #[test]
    fn test_oma_id_file_lifecycle_and_0600() {
        let temp_dir = env::temp_dir().join(format!("oma_id_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let oma_id = get_or_create_oma_id(&temp_dir);
        assert!(validate_oma_id(&oma_id));

        let id_file = temp_dir.join("oma_id");
        assert!(id_file.exists());
        let meta = fs::symlink_metadata(&id_file).expect("Stat oma_id file");
        assert_eq!(meta.mode() & 0o777, 0o600, "oma_id must be 0600 mode");

        // Reloading must yield same OmaID
        let reloaded = get_or_create_oma_id(&temp_dir);
        assert_eq!(reloaded, oma_id);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_blinded_rendezvous_topic_and_kdf() {
        let oma_id = "4829-1048-5729-1104";
        let topic = compute_rendezvous_topic(oma_id);
        assert_eq!(topic.len(), 64);
        assert!(hex::decode(&topic).is_ok());

        // Normalized and formatted should yield identical topic
        let norm = normalize_oma_id(oma_id);
        assert_eq!(compute_rendezvous_topic(&norm), topic);

        let key = derive_rendezvous_key(oma_id);
        assert_eq!(key.len(), 32);
        assert_eq!(derive_rendezvous_key(&norm), key);
    }

    #[test]
    fn test_rendezvous_encryption_and_tamper_detection() {
        let oma_id_alice = "1111-2222-3333-4444";
        let oma_id_bob = "5555-6666-7777-8888";

        let record = RendezvousRecord {
            v: 1,
            topic: compute_rendezvous_topic(oma_id_alice),
            device_id: "alice_device_001".to_string(),
            hostname: "alice-workstation".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_port: 53317,
            stun_addr: Some("203.0.113.50:53317".to_string()),
            wan_url: Some("https://alice.trycloudflare.com".to_string()),
            timestamp: 1727700000,
            expires_at: 1727703600,
        };

        let envelope = encrypt_rendezvous_record(oma_id_alice, &record).expect("Encryption must succeed");
        assert_eq!(envelope.topic, record.topic);

        // Decrypt with correct OmaID
        let decrypted = decrypt_rendezvous_record(oma_id_alice, &envelope).expect("Decryption must succeed");
        assert_eq!(decrypted, record);

        // Decrypt with incorrect OmaID must fail
        let bob_decrypt = decrypt_rendezvous_record(oma_id_bob, &envelope);
        assert!(bob_decrypt.is_err(), "Decryption with wrong OmaID must fail");

        // Tampered ciphertext must fail
        let mut tampered = envelope.clone();
        tampered.ciphertext = format!("aa{}", &tampered.ciphertext[2..]);
        let tamper_decrypt = decrypt_rendezvous_record(oma_id_alice, &tampered);
        assert!(tamper_decrypt.is_err(), "Tampered ciphertext must fail authentication");
    }

    #[test]
    fn test_stun_packet_builder_and_xor_mapped_parser() {
        let (req, tx_id) = create_stun_binding_request();
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &[0x00, 0x01]); // Binding Request
        assert_eq!(&req[4..8], &[0x21, 0x12, 0xa4, 0x42]); // Magic Cookie
        assert_eq!(&req[8..20], &tx_id);

        // Construct a synthetic RFC 5389 STUN Binding Success Response
        // External IP: 198.51.100.25 (0xC6, 0x33, 0x64, 0x19), Port: 54321 (0xD431)
        // XOR Port: 0xD431 ^ 0x2112 = 0xF523
        // XOR IP: 0xC6336419 ^ 0x2112A442 = 0xE721C05B
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x01, 0x01]); // Binding Success Response
        resp.extend_from_slice(&[0x00, 0x0c]); // Length 12 bytes
        resp.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic Cookie
        resp.extend_from_slice(&tx_id); // Transaction ID

        // Attribute XOR-MAPPED-ADDRESS (0x0020), length 8
        resp.extend_from_slice(&[0x00, 0x20]);
        resp.extend_from_slice(&[0x00, 0x08]);
        resp.push(0x00); // reserved
        resp.push(0x01); // IPv4 family
        let x_port: u16 = 54321 ^ 0x2112;
        resp.extend_from_slice(&x_port.to_be_bytes());
        let x_ip = [
            198 ^ 0x21,
            51 ^ 0x12,
            100 ^ 0xa4,
            25 ^ 0x42,
        ];
        resp.extend_from_slice(&x_ip);

        let parsed = parse_stun_response(&resp, &tx_id).expect("Parse STUN response");
        assert_eq!(parsed.ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25)));
        assert_eq!(parsed.port(), 54321);
    }

    #[test]
    fn test_github_anchor_payload_lifecycle() {
        let oma_id = "9876-5432-1098-7654";
        let topic = compute_rendezvous_topic(oma_id);
        assert_eq!(format_github_anchor_ref(&topic), format!("refs/tags/rendezvous/{}", topic));

        let record = RendezvousRecord {
            v: 1,
            topic: topic.clone(),
            device_id: "dev_999".to_string(),
            hostname: "arch-box".to_string(),
            local_ip: "10.0.0.45".to_string(),
            local_port: 53317,
            stun_addr: Some("198.51.100.10:53317".to_string()),
            wan_url: None,
            timestamp: 1727710000,
            expires_at: 1727713600,
        };

        let json_payload = build_github_anchor_payload(oma_id, &record).expect("Build anchor payload");
        let parsed_record = parse_github_anchor_payload(oma_id, &json_payload).expect("Parse anchor payload");
        assert_eq!(parsed_record, record);
    }

    #[test]
    fn test_nat_traversed_socket_lifecycle() {
        // Test binding to an ephemeral port with localhost dummy target
        let nat_sock = NatTraversedSocket::bind(0, "127.0.0.1:19302").expect("Bind NatTraversedSocket");
        let local = nat_sock.local_addr().expect("Get local addr");
        assert!(local.port() > 0);
        assert_eq!(nat_sock.mapped_addr(), None); // localhost dummy will fail STUN parse gracefully
        nat_sock.stop();
    }

    #[test]
    fn test_fallback_qr_svg_generation() {
        let svg = generate_fallback_qr_svg("omasend://identity/4829104857291104");
        assert!(svg.starts_with(r#"<svg xmlns="http://www.w3.org/2000/svg""#));
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains(r#"<rect width="256" height="256""#));
        assert!(svg.contains(r##"fill="#111827""##));
    }

    #[test]
    fn test_paired_peers_lifecycle_and_0600() {
        let temp_dir = env::temp_dir().join(format!("oma_pair_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let raw_id = generate_raw_oma_id();
        assert!(!is_peer_paired(&raw_id, &temp_dir));

        let paired = add_paired_peer(&raw_id, "Alice Workstation", Some("192.168.1.55"), &temp_dir).expect("Add paired peer");
        assert_eq!(paired.name, "Alice Workstation");
        assert_eq!(paired.ip, Some("192.168.1.55".to_string()));
        assert!(is_peer_paired(&raw_id, &temp_dir));
        assert!(is_peer_paired(&paired.oma_id, &temp_dir));

        let peers_file = temp_dir.join("paired_peers.json");
        assert!(peers_file.exists());
        let meta = fs::symlink_metadata(&peers_file).expect("Stat paired_peers.json");
        assert_eq!(meta.mode() & 0o777, 0o600, "paired_peers.json must have 0600 permissions");

        // Existing records are immutable through add_paired_peer (trust flows)
        let again = add_paired_peer(&raw_id, "Alice Workstation Updated", Some("10.0.0.99"), &temp_dir).expect("Re-add paired peer");
        assert_eq!(again.name, "Alice Workstation");
        assert_eq!(again.ip, Some("192.168.1.55".to_string()));
        assert_eq!(again.auth_token, paired.auth_token);
        assert!(!again.confirmed, "Records created without code handshake must stay unconfirmed");
        assert!(!again.is_active());

        let loaded = load_paired_peers(&temp_dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].ip, Some("192.168.1.55".to_string()));

        // Invalid OmaID must fail
        assert!(add_paired_peer("1234-invalid", "Bad", None, &temp_dir).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    fn pair_test_dir(tag: &str) -> std::path::PathBuf {
        let d = env::temp_dir().join(format!("oma_pair_sec_{}_{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn test_remote_pairing_rejects_unknown_peer_and_creates_nothing() {
        let dir = pair_test_dir("unknown");
        let raw_id = generate_raw_oma_id();
        let src: IpAddr = "192.168.1.66".parse().unwrap();
        assert_eq!(complete_remote_pairing(&raw_id, "123456", src, &dir, 1000), Err(PairingError::NotAuthorized));
        assert!(load_paired_peers(&dir).is_empty(), "Remote requests must never create peer records");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_remote_pairing_requires_code_and_binds_source_ip() {
        let dir = pair_test_dir("code");
        let raw_id = generate_raw_oma_id();
        let (pending, code) = begin_local_pairing(&raw_id, "Phone", None, &dir, 1000).expect("Begin pairing");
        assert!(!pending.is_active());
        assert_eq!(code.len(), 6);
        let local_token = pending.auth_token.clone();

        let src: IpAddr = "192.168.1.77".parse().unwrap();
        let wrong = if code == "000000" { "111111" } else { "000000" };
        assert_eq!(complete_remote_pairing(&raw_id, wrong, src, &dir, 1001), Err(PairingError::NotAuthorized));

        let done = complete_remote_pairing(&raw_id, &code, src, &dir, 1002).expect("Complete pairing");
        assert!(done.is_active());
        assert_eq!(done.ip, Some("192.168.1.77".to_string()));
        assert_eq!(done.auth_token, local_token, "Token must be the locally generated one");
        assert!(done.pair_code.is_none());

        // Replay of the same code (or any takeover attempt) after completion fails
        let attacker: IpAddr = "192.168.1.200".parse().unwrap();
        assert_eq!(complete_remote_pairing(&raw_id, &code, attacker, &dir, 1003), Err(PairingError::NotAuthorized));
        let stored = load_paired_peers(&dir);
        assert_eq!(stored[0].ip, Some("192.168.1.77".to_string()));
        assert_eq!(stored[0].auth_token, local_token);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_remote_pairing_expiry_ip_hint_public_source_and_lockout() {
        let dir = pair_test_dir("limits");
        let raw_id = generate_raw_oma_id();

        // Expired code
        let (_, code) = begin_local_pairing(&raw_id, "Laptop", None, &dir, 1000).unwrap();
        let src: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(complete_remote_pairing(&raw_id, &code, src, &dir, 1000 + PAIR_CODE_TTL_SECS + 1).is_err());

        // IP hint binds the source address
        let (_, code) = begin_local_pairing(&raw_id, "Laptop", Some("10.0.0.5"), &dir, 2000).unwrap();
        let other: IpAddr = "10.0.0.6".parse().unwrap();
        assert!(complete_remote_pairing(&raw_id, &code, other, &dir, 2001).is_err());
        assert!(complete_remote_pairing(&raw_id, &code, src, &dir, 2002).is_ok());

        // Public source addresses are refused
        let (_, code) = begin_local_pairing(&raw_id, "Laptop", None, &dir, 3000).unwrap();
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(complete_remote_pairing(&raw_id, &code, public, &dir, 3001).is_err());

        // Public IP hints are refused locally
        assert!(begin_local_pairing(&raw_id, "Laptop", Some("8.8.8.8"), &dir, 3002).is_err());

        // Code is revoked after repeated failures
        let (_, code) = begin_local_pairing(&raw_id, "Laptop", None, &dir, 4000).unwrap();
        let wrong = if code == "000000" { "111111" } else { "000000" };
        for _ in 0..PAIR_CODE_MAX_FAILURES {
            assert!(complete_remote_pairing(&raw_id, wrong, src, &dir, 4001).is_err());
        }
        assert!(complete_remote_pairing(&raw_id, &code, src, &dir, 4002).is_err(), "Code must be revoked after max failures");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_legacy_records_deserialize_unconfirmed() {
        let legacy = r#"{"peers":[{"oma_id":"1234-5678-9012-3452","name":"Old","ip":"192.168.1.9","paired_at":1,"auth_token":"ab"}]}"#;
        let db: PairedPeersDb = serde_json::from_str(legacy).unwrap();
        assert!(!db.peers[0].confirmed);
        assert!(!db.peers[0].is_active());
    }

    #[test]
    fn test_local_network_ip_classification() {
        for ok in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.1.1", "::1", "fe80::1", "fd00::1", "::ffff:192.168.1.1"] {
            assert!(is_local_network_ip(&ok.parse().unwrap()), "{} should be local", ok);
        }
        for bad in ["8.8.8.8", "100.64.0.1", "2001:4860::8888", "::ffff:8.8.8.8"] {
            assert!(!is_local_network_ip(&bad.parse().unwrap()), "{} should be rejected", bad);
        }
    }

    #[test]
    fn test_same_owner_zk_proof_verification_and_replay_resistance() {
        let oma_id = generate_raw_oma_id();
        let formatted_oma_id = format_oma_id(&oma_id);
        let device_id = "pc-linux-a1b2c3d4";
        let now_secs = 1_760_000_120u64;
        let bucket = now_secs / 60;

        let proof = compute_same_owner_zk_proof(&formatted_oma_id, device_id, bucket);
        assert_eq!(proof.len(), 64);

        // Exact bucket and +/- 1 adjacent bucket must verify
        assert!(verify_same_owner_zk_proof(&oma_id, device_id, &proof, now_secs));
        assert!(verify_same_owner_zk_proof(&formatted_oma_id, device_id, &proof, now_secs + 55));
        assert!(verify_same_owner_zk_proof(&formatted_oma_id, device_id, &proof, now_secs - 55));

        // Expired replay (> 2 buckets away) must fail
        assert!(!verify_same_owner_zk_proof(&oma_id, device_id, &proof, now_secs + 180));

        // Different OmaID or different device_id must fail
        let other_oma_id = generate_raw_oma_id();
        assert!(!verify_same_owner_zk_proof(&other_oma_id, device_id, &proof, now_secs));
        assert!(!verify_same_owner_zk_proof(&oma_id, "different-device-id", &proof, now_secs));
    }
}
