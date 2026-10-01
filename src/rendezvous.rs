use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ------------------- CRYPTOGRAPHIC PRIMITIVES (HMAC & HKDF) -------------------

/// Standard RFC 2104 HMAC-SHA256 implementation
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

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    let outer_hash = outer_hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_hash);
    out
}

/// Standard RFC 5869 HKDF-SHA256 extraction & expansion for 32-byte key derivation
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(salt, ikm);
    let mut info_with_counter = Vec::with_capacity(info.len() + 1);
    info_with_counter.extend_from_slice(info);
    info_with_counter.push(0x01);
    hmac_sha256(&prk, &info_with_counter)
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
    sum % 10 == 0
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
    let key = derive_rendezvous_key(oma_id);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("Random nonce failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(record)
        .map_err(|e| format!("Record serialization failed: {}", e))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("AES-256-GCM encryption failed: {}", e))?;

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
    if envelope.topic != expected_topic {
        return Err("Rendezvous topic mismatch for specified OmaID".to_string());
    }

    let key = derive_rendezvous_key(oma_id);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce length; expected 12 bytes".to_string());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_bytes = hex::decode(&envelope.ciphertext)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext_bytes.as_ref())
        .map_err(|e| format!("AES-256-GCM decryption failed: {}", e))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Record deserialization failed: {}", e))
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
    if &buf[4..8] != &[0x21, 0x12, 0xa4, 0x42] {
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
}
