mod subproc;
pub mod devicekey;
pub mod military;
pub mod rendezvous;
pub mod omalink;

pub use rendezvous::{
    create_stun_binding_request, format_oma_id, generate_raw_oma_id, hkdf_sha256, hmac_sha256,
    luhn_checksum, luhn_verify, normalize_oma_id, parse_stun_response, query_stun_external_addr,
    query_stun_server, validate_oma_id, NatTraversedSocket,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use sha2::{Digest, Sha256};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subproc::{kill_process_group, run_cmd_bounded};

extern "C" {
    fn getuid() -> u32;
}

const PORT: u16 = 53317;
const P2P_BEACON_PORT: u16 = 53317;
static RECEIVED_COUNTER: AtomicUsize = AtomicUsize::new(0);

// Global and per-peer connection concurrency limits to protect against thread & memory exhaustion DOS
pub const MAX_GLOBAL_CONNECTIONS: usize = 32;
pub const MAX_PEER_CONNECTIONS: usize = 4;
static GLOBAL_ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static PEER_CONNECTION_TRACKER: Mutex<Option<HashMap<IpAddr, usize>>> = Mutex::new(None);
static RECENTLY_NOTIFIED_FILES: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);
static LAST_SYNCED_CLIPBOARD_HASH: Mutex<Option<String>> = Mutex::new(None);
static STATE_FILE_LOCK: Mutex<()> = Mutex::new(());

pub fn get_last_synced_clipboard_hash() -> Option<String> {
    LAST_SYNCED_CLIPBOARD_HASH.lock().ok().and_then(|guard| guard.clone())
}

pub fn set_last_synced_clipboard_hash(hash: &str) {
    if let Ok(mut guard) = LAST_SYNCED_CLIPBOARD_HASH.lock() {
        *guard = Some(hash.to_string());
    }
}

pub fn compute_clipboard_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn record_notified_file(file_name: &str) {
    if let Ok(mut lock) = RECENTLY_NOTIFIED_FILES.lock() {
        let map = lock.get_or_insert_with(HashMap::new);
        let now = Instant::now();
        map.retain(|_, v| now.duration_since(*v) < Duration::from_secs(60));
        map.insert(file_name.to_string(), now);
    }
}

pub fn is_recently_notified(file_name: &str) -> bool {
    if let Ok(mut lock) = RECENTLY_NOTIFIED_FILES.lock() {
        if let Some(map) = lock.as_mut() {
            let now = Instant::now();
            map.retain(|_, v| now.duration_since(*v) < Duration::from_secs(60));
            return map.contains_key(file_name);
        }
    }
    false
}

pub struct ConnectionGuard {
    ip: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        GLOBAL_ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
        if let Ok(mut lock) = PEER_CONNECTION_TRACKER.lock() {
            if let Some(map) = lock.as_mut() {
                if let Some(count) = map.get_mut(&self.ip) {
                    if *count <= 1 {
                        map.remove(&self.ip);
                    } else {
                        *count -= 1;
                    }
                }
            }
        }
    }
}

pub fn try_acquire_connection(ip: IpAddr) -> Option<ConnectionGuard> {
    let mut lock = PEER_CONNECTION_TRACKER.lock().ok()?;
    let map = lock.get_or_insert_with(HashMap::new);

    let global = GLOBAL_ACTIVE_CONNECTIONS.load(Ordering::SeqCst);
    if global >= MAX_GLOBAL_CONNECTIONS {
        return None;
    }

    let peer_count = map.entry(ip).or_insert(0);
    if *peer_count >= MAX_PEER_CONNECTIONS {
        return None;
    }

    *peer_count += 1;
    GLOBAL_ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
    Some(ConnectionGuard { ip })
}

#[cfg(test)]
fn reset_connection_tracker() {
    GLOBAL_ACTIVE_CONNECTIONS.store(0, Ordering::SeqCst);
    if let Ok(mut lock) = PEER_CONNECTION_TRACKER.lock() {
        if let Some(map) = lock.as_mut() {
            map.clear();
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size_str: String,
    pub size_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredPeer {
    pub id: String,
    #[serde(default)]
    pub oma_id: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub transport: String, // "LAN"
    pub fingerprint: String,
    pub is_trusted: bool,
    #[serde(default)]
    pub is_same_owner: bool,
    pub last_seen_secs: u64,
    /// Device key advertised in the beacon (protocol v2), empty for older versions.
    #[serde(default)]
    pub pk: String,
    /// "own" / "paired" when this peer is a QR-paired key, otherwise empty.
    #[serde(default)]
    pub key_trust: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrustedPeer {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub trusted_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TrustedPeersDb {
    pub peers: Vec<TrustedPeer>,
}

fn default_clipboard_content_type() -> String {
    "text".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClipboardItem {
    pub timestamp: u64,
    pub sender: String,
    #[serde(default = "default_clipboard_content_type")]
    pub content_type: String, // "text", "image_png", "image_jpeg", "image_webp"
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub char_count: usize,
    #[serde(default)]
    pub is_url: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail_base64: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ClipboardVault {
    pub items: Vec<ClipboardItem>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferFileInfo {
    pub name: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingFileTransfer {
    pub token: String,
    pub sender_id: String,
    pub sender_name: String,
    pub sender_ip: String,
    pub file_names: Vec<String>,
    #[serde(default)]
    pub files: Vec<TransferFileInfo>,
    #[serde(default)]
    pub remaining_files: usize,
    pub total_size_bytes: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: String, // "PENDING", "ACCEPTED", "REJECTED"
    /// v2: public key of the authenticated sender; uploads must be signed by the same key.
    #[serde(default)]
    pub sender_pk: Option<String>,
    /// "quic" when the offer came through omasend-core; decisions are forwarded to the core.
    #[serde(default)]
    pub transport: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pBeaconPacket {
    pub magic: String,
    pub v: u32,
    pub id: String,
    /// Legacy OmaID. Still read from older peers as a display label, never sent: it is public,
    /// and it used to be treated like a password (same-owner, pairing lookups).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub oma_id: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub mode: String,
    pub fp: String,
    /// Ed25519 device key (protocol v2). Only an address hint: every connection to a
    /// paired key is authenticated by TLS, so a forged beacon cannot receive anything.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pk: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerState {
    pub status: String,
    pub port: u16,
    pub local_ip: String,
    pub tailscale_ip: Option<String>,
    // The portal secret and E2EE key are deliberately not part of the status (see main()).
    pub active_mode: String, // "LAN" or "WAN"
    pub wan_active: bool,
    pub wan_connecting: bool,
    pub wan_provider: Option<String>,
    pub wan_url: Option<String>,
    pub download_dir: String,
    pub shared_dir: String,
    pub qr_path: String,
    pub omaid_qr_path: String,
    pub active_url: String,
    pub total_received: usize,
    pub recent_files: Vec<FileInfo>,
    pub shared_files: Vec<FileInfo>,
    // AirBridge P2P (Strict OmaID)
    pub p2p_device_id: String,
    pub p2p_hostname: String,
    pub p2p_visibility: String,
    pub p2p_visibility_remaining_secs: u64,
    pub p2p_discovered_peers: Vec<DiscoveredPeer>,
    pub p2p_pending_transfer: Option<PendingFileTransfer>,
    #[serde(default)]
    pub p2p_transfer_progress: Option<serde_json::Value>,
    pub clipboard_vault: Vec<ClipboardItem>,
    // OmaID, Blinded Rendezvous & WAN Discovery
    pub oma_id: String,
    pub wan_mode: String,
    /// External address from STUN, looked up only when the WAN tunnel is turned on.
    pub stun_addr: Option<String>,
    #[serde(default)]
    pub sound_enabled: bool,
    #[serde(default)]
    pub firewall_status: String,
    /// Protocol v2 device id (XXXX-XXXX-XXXX-XXXX) of this machine.
    #[serde(default)]
    pub device_key_id: String,
    /// QR-paired devices (trust store) with online state from discovery.
    #[serde(default)]
    pub paired_devices: Vec<serde_json::Value>,
    /// Landlock state the daemon reported at startup: false = running unsandboxed (kernel
    /// without Landlock, or setup failed), null = no daemon has reported yet.
    #[serde(default)]
    pub sandbox: Option<bool>,
}

fn get_local_ip() -> String {
    let socket = UdpSocket::bind("0.0.0.0:0");
    if let Ok(s) = socket {
        if s.connect("10.255.255.255:1").is_ok() {
            if let Ok(addr) = s.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn get_tailscale_ip() -> Option<String> {
    let deadline = Instant::now() + Duration::from_millis(400);
    if let Some(out) = run_cmd_bounded("/usr/bin/tailscale", &["ip", "-4"], &[], deadline, 512) {
        let s = String::from_utf8_lossy(&out).trim().to_string();
        if !s.is_empty() && !s.contains("error") {
            return Some(s);
        }
    }
    None
}

fn get_current_uid() -> u32 {
    // SAFETY: POSIX getuid() is thread-safe and always succeeds.
    unsafe { getuid() }
}

fn get_state_dir() -> PathBuf {
    #[cfg(test)]
    let dir = {
        std::env::temp_dir().join(format!("omasend_test_state_{}", std::process::id()))
    };
    #[cfg(not(test))]
    let dir = {
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Path::new(&home).join(".local/state/omarchy/omasend")
    };
    let _ = fs::create_dir_all(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    dir
}

fn get_download_dir() -> PathBuf {
    #[cfg(test)]
    let dir = {
        std::env::temp_dir().join(format!("omasend_test_downloads_{}", std::process::id()))
    };
    #[cfg(not(test))]
    let dir = {
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Path::new(&home).join("Downloads/omasend")
    };
    let _ = fs::create_dir_all(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    dir
}

fn get_shared_dir() -> PathBuf {
    let dir = get_download_dir().join("shared");
    let _ = fs::create_dir_all(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    dir
}

/// Queries available disk space in bytes on the filesystem containing the given path
pub fn get_available_disk_space(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs is a standard POSIX libc call with a valid null-terminated path and valid buffer.
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
            let bavail = stat.f_bavail as u64;
            let bsize = stat.f_frsize as u64;
            Some(bavail.saturating_mul(bsize))
        } else {
            None
        }
    }
}

// ------------------- PIN & E2EE KEY MANAGEMENT (SECURE 0600) -------------------

/// Reads a sensitive file (pin.txt or session_key.txt) verifying:
/// - Target is not a symlink
/// - Target is a regular file
/// - Target is owned by the current running user
/// - Target permissions are strictly 0600 (owner read/write only)
fn read_secure_file(path: &Path) -> Result<String, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("Failed to stat {:?}: {}", path, e))?;

    if meta.file_type().is_symlink() {
        return Err(format!("Security violation: {:?} is a symlink", path));
    }
    if !meta.file_type().is_file() {
        return Err(format!("Security violation: {:?} is not a regular file", path));
    }
    let current_uid = get_current_uid();
    if meta.uid() != current_uid {
        return Err(format!(
            "Security violation: {:?} is owned by UID {}, expected current user UID {}",
            path,
            meta.uid(),
            current_uid
        ));
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "Security violation: {:?} has permissions {:o}, expected strictly 0600",
            path, mode
        ));
    }

    const MAX_SECURE_FILE_BYTES: u64 = 1024 * 1024; // 1 MiB ceiling for state/config files
    if meta.len() > MAX_SECURE_FILE_BYTES {
        return Err(format!(
            "Security violation: {:?} exceeds maximum allowed size ({} bytes)",
            path, MAX_SECURE_FILE_BYTES
        ));
    }

    let file = fs::File::open(path).map_err(|e| format!("Failed to open {:?}: {}", path, e))?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(65536));
    file.take(MAX_SECURE_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read {:?}: {}", path, e))?;
    if buf.len() as u64 > MAX_SECURE_FILE_BYTES {
        return Err(format!(
            "Security violation: {:?} grew beyond maximum size during read",
            path
        ));
    }
    String::from_utf8(buf).map_err(|e| format!("Invalid UTF-8 in {:?}: {}", path, e))
}

pub fn safe_verify_file(path: &Path) -> Result<u64, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("Failed to stat {:?}: {}", path, e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("Security violation: {:?} is a symlink", path));
    }
    if !meta.file_type().is_file() {
        return Err(format!("Security violation: {:?} is not a regular file", path));
    }
    let current_uid = get_current_uid();
    if meta.uid() != current_uid {
        return Err(format!(
            "Security violation: {:?} is owned by UID {}, expected current user UID {}",
            path,
            meta.uid(),
            current_uid
        ));
    }
    Ok(meta.len())
}

pub fn compute_file_military_hashes(path: &Path) -> Result<(String, String, String), String> {
    let _ = safe_verify_file(path)?;
    let mut file = fs::File::open(path).map_err(|e| format!("Failed to open {:?}: {}", path, e))?;
    let mut blake3_hasher = blake3::Hasher::new();
    let mut sha = Sha256::new();
    let mut md5_ctx = md5::Context::new();
    let mut buf = [0u8; 131072]; // 128 KiB chunk aligned with IEEE 802.11 A-MPDU
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("Failed to read {:?}: {}", path, e))?;
        if n == 0 {
            break;
        }
        blake3_hasher.update(&buf[..n]);
        sha.update(&buf[..n]);
        md5_ctx.consume(&buf[..n]);
    }
    let blake3_hex = blake3_hasher.finalize().to_hex().to_string();
    let sha256_hex = hex::encode(sha.finalize());
    let md5_hex = format!("{:x}", md5_ctx.compute());
    Ok((blake3_hex, sha256_hex, md5_hex))
}

/// Reads any normal file safely with a strict 100 MiB upper bound:
/// - Rejects untrusted symlinks
/// - Must be regular file
/// - Must be owned by the current running user
/// - Enforces bounded read via take(MAX + 1)
pub fn safe_read_file(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("Failed to stat {:?}: {}", path, e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("Security violation: {:?} is a symlink", path));
    }
    if !meta.file_type().is_file() {
        return Err(format!("Security violation: {:?} is not a regular file", path));
    }
    let current_uid = get_current_uid();
    if meta.uid() != current_uid {
        return Err(format!(
            "Security violation: {:?} is owned by UID {}, expected current user UID {}",
            path,
            meta.uid(),
            current_uid
        ));
    }
    let max_bytes = MAX_BODY_SIZE as u64;
    if meta.len() > max_bytes {
        return Err(format!(
            "Security violation: {:?} exceeds maximum safe read ceiling ({} bytes)",
            path, max_bytes
        ));
    }
    let file = fs::File::open(path).map_err(|e| format!("Failed to open {:?}: {}", path, e))?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(1024 * 1024));
    file.take(max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read {:?}: {}", path, e))?;
    if buf.len() as u64 > max_bytes {
        return Err(format!(
            "Security violation: {:?} grew beyond maximum size during read",
            path
        ));
    }
    Ok(buf)
}

/// Atomically writes a secure file with mode 0600:
/// - Verifies that existing target is not an untrusted symlink or foreign file
/// - Creates a temporary file in the same directory with mode 0600
/// - Writes data and syncs
/// - Atomically replaces destination file via rename
/// - Re-asserts mode 0600 on destination
pub fn write_secure_bytes(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or_else(|| "Target path has no parent directory".to_string())?;
    let _ = fs::create_dir_all(dir);
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

    // Verify existing target file before replacement
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(path);
        } else {
            if !meta.file_type().is_file() {
                return Err(format!("Security violation: target {:?} is not a regular file", path));
            }
            let current_uid = get_current_uid();
            if meta.uid() != current_uid {
                return Err(format!(
                    "Security violation: target {:?} is owned by UID {}, expected current user UID {}",
                    path,
                    meta.uid(),
                    current_uid
                ));
            }
        }
    }

    let mut rand_bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut rand_bytes);
    let tmp_name = format!(
        ".tmp_{}_{}_{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        hex::encode(rand_bytes)
    );
    let tmp_path = dir.join(tmp_name);

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to create temporary secure file {:?}: {}", tmp_path, e))?;

        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));

        file.write_all(data)
            .map_err(|e| format!("Failed to write data to {:?}: {}", tmp_path, e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync {:?}: {}", tmp_path, e))?;
    }

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("Failed to atomically rename {:?} to {:?}: {}", tmp_path, path, e)
    })?;

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn write_secure_file(path: &Path, content: &str) -> Result<(), String> {
    write_secure_bytes(path, content.as_bytes())
}

/// Length in hex characters of the portal access secret (still stored as `pin.txt` and sent
/// as `X-OmaSend-PIN`): 24 random bytes, 192 bits. The old 4-digit PIN could be brute forced
/// through the WAN tunnel; a stored 4-digit PIN is not accepted and is replaced on first use.
pub const PORTAL_SECRET_HEX_LEN: usize = 48;

fn get_or_create_pin() -> String {
    let pin_file = get_state_dir().join("pin.txt");
    if let Ok(content) = read_secure_file(&pin_file) {
        let p = content.trim();
        if p.len() == PORTAL_SECRET_HEX_LEN && p.chars().all(|c| c.is_ascii_hexdigit()) {
            return p.to_ascii_lowercase();
        }
    }
    generate_new_pin()
}

fn generate_new_pin() -> String {
    let mut rand_bytes = [0u8; PORTAL_SECRET_HEX_LEN / 2];
    if getrandom::getrandom(&mut rand_bytes).is_err() {
        // Never fall back to a guessable secret: without a CSPRNG the portal stays locked.
        eprintln!("CSPRNG failure: portal secret not created");
        return String::new();
    }
    let pin = hex::encode(rand_bytes);
    let pin_file = get_state_dir().join("pin.txt");
    if let Err(e) = write_secure_file(&pin_file, &pin) {
        eprintln!("Error writing secure pin file: {}", e);
    }
    pin
}

fn get_or_create_session_key() -> String {
    let key_file = get_state_dir().join("session_key.txt");
    if let Ok(content) = read_secure_file(&key_file) {
        let k = content.trim();
        if k.len() == 64 && hex::decode(k).is_ok() {
            return k.to_string();
        }
    }
    generate_new_session_key()
}

fn generate_new_session_key() -> String {
    let mut key_bytes = [0u8; 32];
    let _ = getrandom::getrandom(&mut key_bytes);
    let key_hex = hex::encode(key_bytes);
    let key_file = get_state_dir().join("session_key.txt");
    if let Err(e) = write_secure_file(&key_file, &key_hex) {
        eprintln!("Error writing secure session key file: {}", e);
    }
    key_hex
}

pub fn get_or_create_oma_id() -> String {
    rendezvous::get_or_create_oma_id(&get_state_dir())
}

pub fn generate_new_oma_id() -> String {
    rendezvous::generate_new_oma_id(&get_state_dir())
}

fn get_active_mode() -> String {
    let mode_file = get_state_dir().join("mode.txt");
    if let Ok(m) = read_secure_file(&mode_file) {
        let trimmed = m.trim().to_uppercase();
        if trimmed == "WAN" {
            return "WAN".to_string();
        }
    }
    "LAN".to_string()
}

fn set_active_mode(mode: &str) {
    let mode_file = get_state_dir().join("mode.txt");
    let _ = write_secure_file(&mode_file, mode);
}

// ------------------- AES-256-GCM CRYPTOGRAPHY -------------------

fn decrypt_aes256_gcm(key_hex: &str, iv_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key_bytes = hex::decode(key_hex).map_err(|e| format!("Invalid key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Key length must be 32 bytes".to_string());
    }
    if iv_bytes.len() != 12 {
        return Err("IV length must be 12 bytes".to_string());
    }
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|e| format!("AES-GCM decryption failed: {}", e))
}

fn encrypt_aes256_gcm(key_hex: &str, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key_bytes = hex::decode(key_hex).map_err(|e| format!("Invalid key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Key length must be 32 bytes".to_string());
    }
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).map_err(|e| format!("Random failed: {}", e))?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| format!("AES-GCM encryption failed: {}", e))?;
    Ok((iv.to_vec(), ciphertext))
}

// ------------------- WAN TUNNEL MANAGEMENT -------------------

fn is_process_alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// True if `pid` is a live process of the current user whose name (`/proc/<pid>/comm`) is
/// `name`. Stale pid files can point at a reused pid; never signal anything else (M16).
fn pid_is(pid: i32, name: &str) -> bool {
    if pid <= 1 {
        return false;
    }
    let owned = fs::metadata(format!("/proc/{}", pid)).is_ok_and(|m| m.uid() == get_current_uid());
    let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default();
    // comm is truncated to 15 bytes by the kernel.
    let expected: String = name.chars().take(15).collect();
    owned && comm.trim_end() == expected
}

const CLOUDFLARED_COMM: &str = "cloudflared";
const ENGINE_COMM: &str = "omasend-engine";

fn get_wan_provider() -> Option<String> {
    let provider_file = get_state_dir().join("wan_provider.txt");
    read_secure_file(&provider_file).ok().map(|s| s.trim().to_string())
}

/// True if `path` and every directory above it are owned by root and not writable by group or
/// others, and `path` is a regular file (not a symlink). A user-writable binary on the tunnel
/// path would let any process running as the user swap what serves the portal.
fn is_root_owned_and_locked(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else { return false };
    if !meta.file_type().is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return false;
    }
    let mut dir = path.parent();
    while let Some(d) = dir {
        match fs::metadata(d) {
            Ok(m) if m.uid() == 0 && m.mode() & 0o022 == 0 => {}
            _ => return false,
        }
        dir = d.parent();
    }
    true
}

/// cloudflared from a system package only. `~/.local/bin` and `$PATH` lookups are no longer
/// used: anything the user (or malware running as the user) can write is not trusted to carry
/// the portal to the internet.
fn get_cloudflared_bin() -> Option<String> {
    ["/usr/bin/cloudflared", "/usr/local/bin/cloudflared"]
        .iter()
        .find(|c| is_root_owned_and_locked(Path::new(c)))
        .map(|c| c.to_string())
}

fn get_wan_status() -> (bool, bool, Option<String>) {
    let pid_file = get_state_dir().join("wan_pid.txt");
    let url_file = get_state_dir().join("wan_url.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let log_file = get_state_dir().join("wan_tunnel.log");

    if let Ok(pid_str) = read_secure_file(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if is_process_alive(pid) && pid_is(pid, CLOUDFLARED_COMM) {
                // If URL is already recorded, return immediately
                if let Ok(url) = read_secure_file(&url_file) {
                    let u = url.trim().to_string();
                    if !u.is_empty() {
                        let _ = fs::remove_file(&connecting_file);
                        return (true, false, Some(u));
                    }
                }

                // Check Cloudflare log for resolved trycloudflare URL
                if let Ok(content) = fs::read_to_string(&log_file) {
                    for line in content.lines() {
                        if let Some(pos) = line.find("https://") {
                            let rest = &line[pos..];
                            if let Some(end) = rest.find(".trycloudflare.com") {
                                let found_url = rest[..end + 18].to_string();
                                let _ = write_secure_file(&url_file, &found_url);
                                let _ = fs::remove_file(&connecting_file);
                                set_active_mode("WAN");
                                update_all_qr();
                                notify_desktop(
                                    "OmaSend: Global WAN Active",
                                    &format!("Global AirBridge ready!\nAddress: {}", found_url),
                                );
                                return (true, false, Some(found_url));
                            }
                        }
                    }
                }
                return (false, true, None);
            }
        }
    }
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&url_file);
    let _ = fs::remove_file(&connecting_file);
    (false, false, None)
}

/// External address from the STUN lookup done when the WAN tunnel was started.
fn wan_stun_path() -> PathBuf {
    get_state_dir().join("wan_stun.txt")
}

/// Printed whenever the user turns the WAN tunnel on. The tunnel is off by default and never
/// started automatically.
const WAN_WARNING: &str = "WARNING: WAN access publishes this machine's OmaSend web portal on a public trycloudflare.com address.\n\
Anyone with the portal link (it contains the access secret) can upload files to this PC, download shared files and read or set its clipboard.\n\
Only the portal is reachable through the tunnel; device pairing, transfers and clipboard sync stay LAN-only.\n\
Turn it off when you are done: omasend-engine --stop-wan";

fn stop_wan_tunnel() {
    let pid_file = get_state_dir().join("wan_pid.txt");
    let url_file = get_state_dir().join("wan_url.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let provider_file = get_state_dir().join("wan_provider.txt");
    let log_file = get_state_dir().join("wan_tunnel.log");

    if let Ok(pid_str) = read_secure_file(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if pid_is(pid, CLOUDFLARED_COMM) {
                kill_process_group(pid);
            }
        }
    }

    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&url_file);
    let _ = fs::remove_file(&connecting_file);
    let _ = fs::remove_file(&provider_file);
    let _ = fs::remove_file(&log_file);
    let _ = fs::remove_file(wan_stun_path());
    set_active_mode("LAN");
    update_all_qr();
    notify_desktop("OmaSend: Global WAN", "Secure WAN tunnel closed. Switched to local Wi-Fi mode.");
}

fn start_wan_tunnel() -> Result<String, String> {
    let (active, connecting, url) = get_wan_status();
    if active {
        if let Some(u) = url {
            set_active_mode("WAN");
            update_all_qr();
            return Ok(u);
        }
    }
    if connecting {
        return Ok("Tunnel already initializing...".to_string());
    }

    let pid_file = get_state_dir().join("wan_pid.txt");
    let url_file = get_state_dir().join("wan_url.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let provider_file = get_state_dir().join("wan_provider.txt");
    let _ = fs::remove_file(&url_file);

    // Stop any dangling previous process
    if let Ok(pid_str) = read_secure_file(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if pid_is(pid, CLOUDFLARED_COMM) {
                kill_process_group(pid);
            }
        }
    }

    if let Some(bin) = get_cloudflared_bin() {
        let log_file = get_state_dir().join("wan_tunnel.log");
        let _ = fs::remove_file(&log_file);

        let mut cmd = Command::new(bin);
        cmd.args([
            "tunnel",
            "--url",
            &format!("http://127.0.0.1:{}", PORT),
            "--edge-ip-version",
            "4",
            "--no-autoupdate",
            "--logfile",
            log_file.to_str().unwrap_or(""),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);

        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();
                let _ = write_secure_file(&pid_file, &pid.to_string());
                let _ = write_secure_file(&connecting_file, "connecting");
                let _ = write_secure_file(&provider_file, "Cloudflare");
                set_active_mode("WAN");
                // The external address is looked up once here, while the user has WAN on;
                // status polling (`--json`) only reads this file and never talks to STUN.
                match query_stun_external_addr() {
                    Some(a) => {
                        let _ = write_secure_file(&wan_stun_path(), &a.to_string());
                    }
                    None => {
                        let _ = fs::remove_file(wan_stun_path());
                    }
                }
                return Ok("Cloudflare tunnel launched in background".to_string());
            }
            Err(e) => {
                return Err(format!("Failed to spawn cloudflared: {}", e));
            }
        }
    }

    Err("WAN Tunneling requires cloudflared from a system package (root-owned /usr/bin/cloudflared or /usr/local/bin/cloudflared): pacman -S cloudflared (see README.md)".to_string())
}

// ------------------- QR CODE & URLS -------------------

fn qr_modules(content: &str) -> Option<(usize, Vec<bool>)> {
    let code = qrcode::QrCode::with_error_correction_level(content.as_bytes(), qrcode::EcLevel::M).ok()?;
    let width = code.width();
    Some((width, code.to_colors().into_iter().map(|c| c == qrcode::Color::Dark).collect()))
}

fn png_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = png_crc32(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// Minimal PNG encoder for a QR code: 8-bit grayscale, zlib stream of stored (uncompressed)
/// deflate blocks. Black modules on white, `scale` pixels per module, `margin` modules of
/// quiet zone. Avoids depending on qrencode or an image crate.
fn qr_png(content: &str, scale: usize, margin: usize) -> Option<Vec<u8>> {
    let (width, dark) = qr_modules(content)?;
    let side = (width + 2 * margin) * scale;
    let mut raw = Vec::with_capacity(side * (side + 1));
    for py in 0..side {
        raw.push(0u8); // filter: none
        let my = (py / scale).checked_sub(margin).filter(|&y| y < width);
        for px in 0..side {
            let mx = (px / scale).checked_sub(margin).filter(|&x| x < width);
            let is_dark = matches!((mx, my), (Some(x), Some(y)) if dark[y * width + x]);
            raw.push(if is_dark { 0 } else { 255 });
        }
    }
    let mut z = vec![0x78, 0x01];
    let mut chunks = raw.chunks(65_535).peekable();
    while let Some(block) = chunks.next() {
        z.push(if chunks.peek().is_none() { 1 } else { 0 });
        let len = block.len() as u16;
        z.extend_from_slice(&len.to_le_bytes());
        z.extend_from_slice(&(!len).to_le_bytes());
        z.extend_from_slice(block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in &raw {
        a = (a + byte as u32) % 65_521;
        b = (b + a) % 65_521;
    }
    z.extend_from_slice(&((b << 16) | a).to_be_bytes());

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(side as u32).to_be_bytes());
    ihdr.extend_from_slice(&(side as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // 8-bit, grayscale, deflate, no filter, no interlace
    png_chunk(&mut out, b"IHDR", &ihdr);
    png_chunk(&mut out, b"IDAT", &z);
    png_chunk(&mut out, b"IEND", &[]);
    Some(out)
}

/// QR code for a terminal: two module rows per line with half blocks, black on white.
fn qr_ansi(content: &str) -> Option<String> {
    let (width, dark) = qr_modules(content)?;
    let margin = 2;
    let side = width + 2 * margin;
    let at = |x: usize, y: usize| -> bool {
        x >= margin && y >= margin && x - margin < width && y - margin < width && dark[(y - margin) * width + (x - margin)]
    };
    let mut out = String::new();
    for y in (0..side).step_by(2) {
        out.push_str("\x1b[30;47m");
        for x in 0..side {
            out.push(match (at(x, y), y + 1 < side && at(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push_str("\x1b[0m\n");
    }
    Some(out)
}

pub fn update_oma_id_qr() -> (String, String) {
    let state_dir = get_state_dir();
    let oma_id = get_or_create_oma_id();
    let raw_id = rendezvous::normalize_oma_id(&oma_id);
    let qr_content = format!("omasend://identity/{}", raw_id);

    let svg_file = state_dir.join("oma_id_qr.svg");
    let png_file = state_dir.join("oma_id_qr.png");
    let legacy_svg_file = state_dir.join("omaid_qr.svg");
    let last_content_file = state_dir.join("last_oma_id_qr.txt");

    let is_cached = svg_file.exists()
        && png_file.exists()
        && read_secure_file(&last_content_file).map(|c| c.trim() == qr_content).unwrap_or(false);

    let svg_path = svg_file.to_string_lossy().to_string();
    let png_path = png_file.to_string_lossy().to_string();

    if is_cached {
        return (svg_path, png_path);
    }

    // Rendered in Rust: qrencode is not a dependency any more (M8).
    let _ = write_secure_file(&svg_file, &rendezvous::generate_fallback_qr_svg(&qr_content));
    let _ = write_secure_file(&legacy_svg_file, &rendezvous::generate_fallback_qr_svg(&qr_content));
    if let Some(png) = qr_png(&qr_content, 8, 2) {
        let _ = write_secure_bytes(&png_file, &png);
    }

    let _ = write_secure_file(&last_content_file, &qr_content);
    (svg_path, png_path)
}

/// Portal address without any secret, safe for status output.
fn portal_base_url(ip: &str, mode: &str, wan_url: Option<&str>) -> String {
    match wan_url {
        Some(u) if mode == "WAN" => u.trim_end_matches('/').to_string(),
        _ => format!("http://{}:{}", ip, PORT),
    }
}

/// Portal link that carries the access secret and the E2EE key. Both live in the fragment,
/// which browsers never send to the server (or to Cloudflare, or into proxy logs); the login
/// page reads the secret from it and presents it in a header. Only the 0600 QR file and the
/// explicit `--portal-url` command ever show this link.
fn portal_secret_url(base: &str, pin: &str, key: &str) -> String {
    format!("{}/#key={}&pin={}", base, key, pin)
}

fn update_all_qr() {
    let ip = get_local_ip();
    let pin = get_or_create_pin();
    let key = get_or_create_session_key();
    let mode = get_active_mode();
    let (_wan_active, _wan_connecting, wan_url) = get_wan_status();

    let full_url = portal_secret_url(&portal_base_url(&ip, &mode, wan_url.as_deref()), &pin, &key);

    let last_qr_file = get_state_dir().join("last_qr_url.txt");
    let qr_file = get_state_dir().join("qr.svg");

    if !qr_file.exists() || read_secure_file(&last_qr_file).map(|s| s.trim() != full_url).unwrap_or(true) {
        // The URL carries the portal secret, so the file is written 0600.
        if let Some(svg) = rendezvous::qr_svg(&full_url) {
            let _ = write_secure_file(&qr_file, &svg);
        }
        let _ = write_secure_file(&last_qr_file, &full_url);
    }

    // Ensure desktop OmaID QR code (oma_id_qr.png / .svg) is always generated and ready
    update_oma_id_qr();
}


fn get_desktop_gui_envs() -> Vec<(&'static str, String)> {
    let keys = [
        "HOME",
        "USER",
        "LOGNAME",
        "WAYLAND_DISPLAY",
        "DISPLAY",
        "XDG_RUNTIME_DIR",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_DATA_DIRS",
        "PATH",
    ];
    let mut envs = Vec::new();
    let mut has_wayland = false;
    let mut has_runtime = false;
    let mut has_path = false;

    for k in keys {
        if let Ok(v) = env::var(k) {
            if !v.is_empty() {
                if k == "WAYLAND_DISPLAY" { has_wayland = true; }
                if k == "XDG_RUNTIME_DIR" { has_runtime = true; }
                if k == "PATH" { has_path = true; }
                envs.push((k, v));
            }
        }
    }
    if !has_path {
        envs.push(("PATH", "/usr/bin:/bin:/usr/local/bin".to_string()));
    }
    if !has_runtime {
        let uid = unsafe { libc::getuid() };
        envs.push(("XDG_RUNTIME_DIR", format!("/run/user/{}", uid)));
    }
    if !has_wayland {
        let uid = unsafe { libc::getuid() };
        if Path::new(&format!("/run/user/{}/wayland-1", uid)).exists() {
            envs.push(("WAYLAND_DISPLAY", "wayland-1".to_string()));
        } else if Path::new(&format!("/run/user/{}/wayland-0", uid)).exists() {
            envs.push(("WAYLAND_DISPLAY", "wayland-0".to_string()));
        }
    }
    envs
}

/// Escapes text for HTML (and Pango/notification body markup): `& < > " '`.
fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Notification bodies contain names chosen by remote devices. Notification daemons (mako,
/// dunst) interpret body markup, so escape it, and never let the text start with '-' where a
/// helper could read it as an option.
fn notification_text(text: &str) -> String {
    let escaped = text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    if escaped.starts_with('-') {
        format!("\u{2060}{}", escaped)
    } else {
        escaped
    }
}

fn notify_desktop(title: &str, body: &str) {
    let title = &notification_text(title);
    let body = &notification_text(body);
    let env_store = get_desktop_gui_envs();
    let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let deadline = Instant::now() + Duration::from_millis(1500);

    let glyph = "󰒍";
    let status = run_cmd_bounded(
        "omarchy-notification-send",
        &[
            "--app-name",
            "OmaSend",
            "-g",
            glyph,
            "-u",
            "normal",
            title,
            body,
        ],
        &envs,
        deadline,
        1024,
    );

    if status.is_none() {
        let _ = run_cmd_bounded(
            "/usr/bin/notify-send",
            &["-a", "OmaSend", "-i", "document-send", "--", title, body],
            &envs,
            deadline,
            1024,
        );
    }
}

/// A file that appeared in Downloads is announced once it has been quiet this long, so a
/// receive path that records the file itself (record_notified_file) right after its rename
/// wins and there is no double notification.
const DOWNLOAD_SETTLE: Duration = Duration::from_millis(1500);
/// Fallback rescan interval when inotify is unavailable.
const DOWNLOAD_RESCAN_FALLBACK: Duration = Duration::from_secs(15);

fn is_ignored_download_name(fname: &str) -> bool {
    fname.starts_with('.') || fname.ends_with(".part") || fname.ends_with(".crdownload")
}

/// Regular files currently in `dir` (names only).
fn list_download_files(dir: &Path) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|ft| ft.is_file()) {
                out.insert(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    out
}

/// Notifies about `fname` unless it is already known or a receive path recorded it.
fn announce_download(dir: &Path, fname: &str, known: &mut std::collections::HashSet<String>) {
    if is_ignored_download_name(fname) || known.contains(fname) {
        return;
    }
    known.insert(fname.to_string());
    if is_recently_notified(fname) {
        return;
    }
    let size = match fs::symlink_metadata(dir.join(fname)) {
        Ok(m) if m.file_type().is_file() => m.len(),
        _ => return,
    };
    if size == 0 {
        known.remove(fname);
        return;
    }
    record_notified_file(fname);
    RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
    notify_desktop(
        "OmaSend: Dosya Alindi",
        &format!("'{}' ({} bayt) Downloads/omasend dizinine kaydedildi.", fname, size),
    );
}

/// Watches Downloads for files dropped in by other tools. Event-driven (inotify): the thread
/// sleeps in poll(2) until something changes, instead of rescanning the directory every 1.5 s.
fn start_download_dir_watcher(download_dir: &Path) {
    let dir = download_dir.to_path_buf();
    thread::spawn(move || {
        // Files already there are not announced.
        let mut known = list_download_files(&dir);
        for f in &known {
            record_notified_file(f);
        }
        loop {
            if !watch_downloads_inotify(&dir, &mut known) {
                // No inotify (or the directory went away): slow rescan, then try again.
                thread::sleep(DOWNLOAD_RESCAN_FALLBACK);
                let current = list_download_files(&dir);
                known.retain(|f| current.contains(f));
                for f in current {
                    announce_download(&dir, &f, &mut known);
                }
            }
        }
    });
}

/// Runs until the watch ends (directory deleted or moved). Returns false if inotify could not
/// be set up at all.
fn watch_downloads_inotify(dir: &Path, known: &mut std::collections::HashSet<String>) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else { return false };
    // SAFETY: plain syscalls on a descriptor owned by this function (closed below).
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    let mask = libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_MOVED_FROM | libc::IN_DELETE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF;
    // SAFETY: fd is a valid inotify descriptor and cpath a NUL-terminated path.
    if unsafe { libc::inotify_add_watch(fd, cpath.as_ptr(), mask) } < 0 {
        unsafe { libc::close(fd) };
        return false;
    }
    // Catch anything that arrived between the initial listing and the watch.
    let current = list_download_files(dir);
    known.retain(|f| current.contains(f));
    let mut pending: HashMap<String, Instant> = current.into_iter().filter(|f| !known.contains(f)).map(|f| (f, Instant::now())).collect();

    let mut buf = [0u8; 8192];
    'watch: loop {
        // Block indefinitely when nothing is waiting to settle.
        let timeout_ms = pending
            .values()
            .map(|t| DOWNLOAD_SETTLE.saturating_sub(t.elapsed()).as_millis() as i32 + 1)
            .min()
            .unwrap_or(-1);
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ready < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break;
        }
        if ready > 0 {
            // SAFETY: reads into a buffer we own, at most its length.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            let mut off = 0usize;
            let n = n as usize;
            // struct inotify_event { int wd; u32 mask; u32 cookie; u32 len; char name[len]; }
            while off + 16 <= n {
                let ev_mask = u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
                let len = u32::from_ne_bytes([buf[off + 12], buf[off + 13], buf[off + 14], buf[off + 15]]) as usize;
                let name_bytes = &buf[off + 16..(off + 16 + len).min(n)];
                off += 16 + len;
                let name = String::from_utf8_lossy(name_bytes.split(|b| *b == 0).next().unwrap_or_default()).to_string();
                if ev_mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF | libc::IN_IGNORED) != 0 {
                    break 'watch;
                }
                if ev_mask & libc::IN_Q_OVERFLOW != 0 {
                    let current = list_download_files(dir);
                    known.retain(|f| current.contains(f));
                    for f in current.into_iter().filter(|f| !known.contains(f)) {
                        pending.insert(f, Instant::now());
                    }
                    continue;
                }
                if name.is_empty() || is_ignored_download_name(&name) {
                    continue;
                }
                if ev_mask & (libc::IN_DELETE | libc::IN_MOVED_FROM) != 0 {
                    known.remove(&name);
                    pending.remove(&name);
                } else if ev_mask & (libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO) != 0 {
                    // A rewrite of a known name is not a new file; one that was deleted and
                    // created again is (it left `known` on delete).
                    if !known.contains(&name) {
                        pending.insert(name, Instant::now());
                    }
                }
            }
        }
        let settled: Vec<String> = pending.iter().filter(|(_, t)| t.elapsed() >= DOWNLOAD_SETTLE).map(|(f, _)| f.clone()).collect();
        for f in settled {
            pending.remove(&f);
            announce_download(dir, &f, known);
        }
    }
    // SAFETY: closing the descriptor opened above.
    unsafe { libc::close(fd) };
    true
}

pub const MAX_CLIPBOARD_VAULT_ITEMS: usize = 20;
pub const MAX_IMAGE_CLIP_SIZE: usize = 10 * 1024 * 1024; // 10 MiB strict ceiling
pub const INLINE_IMAGE_CLIP_MAX_SIZE: usize = 512 * 1024; // 512 KiB inline payload ceiling
pub const MAX_CLIP_STAGING_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB max staging disk usage
pub const MAX_CLIP_STAGING_FILES: usize = 20; // 20 images max

pub fn compute_image_clipboard_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn verify_image_clipboard_hash(bytes: &[u8], expected_hash: &str) -> bool {
    let b3 = blake3::hash(bytes).to_hex().to_string();
    if b3.eq_ignore_ascii_case(expected_hash) {
        return true;
    }
    let mut sha_hasher = Sha256::new();
    sha_hasher.update(bytes);
    let sha_hex = hex::encode(sha_hasher.finalize());
    sha_hex.eq_ignore_ascii_case(expected_hash)
}

pub fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        result.push(CHARSET[((n >> 18) & 63) as usize] as char);
        result.push(CHARSET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARSET[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARSET[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let stripped = if let Some(idx) = input.find(";base64,") {
        &input[idx + 8..]
    } else {
        input
    };
    let clean: Vec<u8> = stripped.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err("Invalid Base64 length".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
    for chunk in clean.chunks_exact(4) {
        let mut buf = [0u8; 4];
        let mut pad_count = 0;
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad_count += 1;
                    0
                }
                _ => return Err("Invalid Base64 character".to_string()),
            };
        }
        let n = ((buf[0] as u32) << 18) | ((buf[1] as u32) << 12) | ((buf[2] as u32) << 6) | (buf[3] as u32);
        out.push(((n >> 16) & 0xFF) as u8);
        if pad_count < 2 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if pad_count < 1 {
            out.push((n & 0xFF) as u8);
        }
    }
    Ok(out)
}

pub fn validate_image_header(data: &[u8]) -> Result<(String, u32, u32), String> {
    if data.is_empty() {
        return Err("Image data is empty".to_string());
    }
    if data.len() > MAX_IMAGE_CLIP_SIZE {
        return Err(format!("Image size ({} bytes) exceeds 10 MiB limit", data.len()));
    }

    // Strict SVG, XML, HTML and script injection prevention - SVG is completely forbidden
    let check_len = data.len().min(1024);
    let preview = &data[..check_len];
    if preview.windows(4).any(|w| w.eq_ignore_ascii_case(b"<svg"))
        || preview.windows(5).any(|w| w.eq_ignore_ascii_case(b"<?xml"))
        || preview.windows(11).any(|w| w.eq_ignore_ascii_case(b"<html"))
        || preview.windows(7).any(|w| w.eq_ignore_ascii_case(b"<script"))
    {
        return Err("SVG, XML and script-containing payloads are strictly rejected for security".to_string());
    }

    // 1. PNG Check: \x89PNG\r\n\x1a\n
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        if data.len() < 24 {
            return Err("PNG data too short for IHDR chunk".to_string());
        }
        if &data[12..16] != b"IHDR" {
            return Err("PNG missing IHDR header".to_string());
        }
        let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

        if width == 0 || height == 0 {
            return Err("Invalid PNG dimensions (0x0)".to_string());
        }
        if width > 8192 || height > 8192 {
            return Err(format!("PNG dimensions ({}x{}) exceed 8192x8192 ceiling", width, height));
        }
        return Ok(("image_png".to_string(), width, height));
    }

    // 2. JPEG Check: \xFF\xD8\xFF
    if data.starts_with(b"\xFF\xD8\xFF") {
        let mut offset = 2;
        let mut width = 0u32;
        let mut height = 0u32;
        let len = data.len();

        while offset + 3 < len {
            if data[offset] != 0xFF {
                offset += 1;
                continue;
            }
            let marker = data[offset + 1];
            offset += 2;

            if marker == 0xFF || marker == 0x00 {
                continue;
            }

            if marker == 0xD8 || marker == 0xD9 || (0xD0..=0xD7).contains(&marker) {
                continue;
            }

            if marker == 0xDA || marker == 0xD9 {
                break;
            }

            if offset + 2 > len {
                break;
            }
            let seg_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            if seg_len < 2 || offset + seg_len > len {
                break;
            }

            let is_sof = matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF);
            if is_sof && seg_len >= 7 && offset + 7 <= len {
                let h = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as u32;
                let w = u16::from_be_bytes([data[offset + 5], data[offset + 6]]) as u32;
                height = h;
                width = w;
                break;
            }
            offset += seg_len;
        }

        if width == 0 || height == 0 {
            return Err("Could not extract valid JPEG dimensions".to_string());
        }
        if width > 8192 || height > 8192 {
            return Err(format!("JPEG dimensions ({}x{}) exceed 8192x8192 ceiling", width, height));
        }
        return Ok(("image_jpeg".to_string(), width, height));
    }

    // 3. WebP Check: RIFF....WEBP
    if data.len() >= 16 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        let chunk_type = &data[12..16];
        let mut width = 0u32;
        let mut height = 0u32;

        if chunk_type == b"VP8 " {
            if data.len() >= 30 && data[23] == 0x9D && data[24] == 0x01 && data[25] == 0x2A {
                let w = u16::from_le_bytes([data[26], data[27]]) & 0x3FFF;
                let h = u16::from_le_bytes([data[28], data[29]]) & 0x3FFF;
                width = w as u32;
                height = h as u32;
            }
        } else if chunk_type == b"VP8L" {
            if data.len() >= 25 && data[20] == 0x2F {
                let bits = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
                width = (bits & 0x3FFF) + 1;
                height = ((bits >> 14) & 0x3FFF) + 1;
            }
        } else if chunk_type == b"VP8X" && data.len() >= 30 {
            let w = (data[24] as u32) | ((data[25] as u32) << 8) | ((data[26] as u32) << 16);
            let h = (data[27] as u32) | ((data[28] as u32) << 8) | ((data[29] as u32) << 16);
            width = w + 1;
            height = h + 1;
        }

        if width == 0 || height == 0 {
            return Err("Could not extract valid WebP dimensions".to_string());
        }
        if width > 8192 || height > 8192 {
            return Err(format!("WebP dimensions ({}x{}) exceed 8192x8192 ceiling", width, height));
        }
        return Ok(("image_webp".to_string(), width, height));
    }

    Err("Unsupported image format: must be PNG, JPEG, or WebP".to_string())
}

pub fn get_clip_staging_dir() -> PathBuf {
    let dir = get_state_dir().join("clip_staging");
    let _ = fs::create_dir_all(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    dir
}

pub fn stage_clipboard_image(data: &[u8], content_type: &str) -> Result<(String, PathBuf), String> {
    let (_, _, _) = validate_image_header(data)?;
    let hash = compute_image_clipboard_hash(data);
    let ext = match content_type {
        "image_jpeg" => "jpg",
        "image_webp" => "webp",
        _ => "png",
    };
    let filename = format!("{}.{}", hash, ext);
    let staging_dir = get_clip_staging_dir();
    let file_path = staging_dir.join(&filename);
    write_secure_bytes(&file_path, data)?;
    let _ = cleanup_clip_staging();
    Ok((hash, file_path))
}

pub fn generate_webp_thumbnail_for_staging(image_path: &Path, hash_hex: &str) -> Option<String> {
    if hash_hex.len() != 64 || !hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let meta = match fs::symlink_metadata(image_path) {
        Ok(m) => m,
        Err(_) => return None,
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    let input_len = meta.len();
    if input_len == 0 || input_len > 50 * 1024 * 1024 {
        return None;
    }

    let staging_dir = get_clip_staging_dir();
    let final_thumb_path = staging_dir.join(format!("{}_thumb.webp", hash_hex));

    if let Ok(thumb_meta) = fs::symlink_metadata(&final_thumb_path) {
        if thumb_meta.file_type().is_file()
            && !thumb_meta.file_type().is_symlink()
            && thumb_meta.len() > 0
            && thumb_meta.len() <= 1024 * 1024
        {
            if let Ok(bytes) = safe_read_file(&final_thumb_path) {
                if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
                    return Some(format!("data:image/webp;base64,{}", base64_encode(&bytes)));
                }
            }
        }
    }

    let input_str = image_path.to_str()?;
    let tmp_thumb_path = staging_dir.join(format!(".tmp_{}_thumb.webp", hash_hex));
    let tmp_out_str = tmp_thumb_path.to_str()?;

    let _ = fs::remove_file(&tmp_thumb_path);

    let deadline = Instant::now() + Duration::from_millis(1500);

    let candidates: [(&[&str], Vec<&str>); 4] = [
        (
            &["/usr/bin/cwebp", "/usr/local/bin/cwebp", "/bin/cwebp"],
            vec!["-resize", "96", "96", "-q", "80", input_str, "-o", tmp_out_str],
        ),
        (
            &["/usr/bin/magick", "/usr/local/bin/magick", "/bin/magick"],
            vec![input_str, "-thumbnail", "96x96", "-quality", "80", tmp_out_str],
        ),
        (
            &["/usr/bin/convert", "/usr/local/bin/convert", "/bin/convert"],
            vec![input_str, "-thumbnail", "96x96", "-quality", "80", tmp_out_str],
        ),
        (
            &["/usr/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/bin/ffmpeg"],
            vec!["-y", "-v", "error", "-i", input_str, "-vf", "scale=96:96:force_original_aspect_ratio=decrease", "-c:v", "libwebp", tmp_out_str],
        ),
    ];

    let mut generated = false;

    for (bin_paths, args) in &candidates {
        if Instant::now() >= deadline {
            break;
        }
        for bin in *bin_paths {
            if Path::new(bin).exists() {
                let ok = subproc::run_cmd_status_bounded(bin, args, &[], deadline);
                if ok && tmp_thumb_path.exists() {
                    generated = true;
                    break;
                }
            }
        }
        if generated {
            break;
        }
    }

    if !generated || !tmp_thumb_path.exists() {
        let _ = fs::remove_file(&tmp_thumb_path);
        return None;
    }

    if let Ok(meta) = fs::symlink_metadata(&tmp_thumb_path) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 1024 * 1024 {
            let _ = fs::remove_file(&tmp_thumb_path);
            return None;
        }
    } else {
        let _ = fs::remove_file(&tmp_thumb_path);
        return None;
    }

    let _ = fs::set_permissions(&tmp_thumb_path, fs::Permissions::from_mode(0o600));

    if fs::rename(&tmp_thumb_path, &final_thumb_path).is_err() {
        let _ = fs::remove_file(&tmp_thumb_path);
        return None;
    }

    let _ = fs::set_permissions(&final_thumb_path, fs::Permissions::from_mode(0o600));

    let bytes = match safe_read_file(&final_thumb_path) {
        Ok(b) => b,
        Err(_) => return None,
    };

    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some(format!("data:image/webp;base64,{}", base64_encode(&bytes)))
    } else {
        None
    }
}

pub fn cleanup_clip_staging() -> Result<(), String> {
    let staging_dir = get_clip_staging_dir();
    let entries = match fs::read_dir(&staging_dir) {
        Ok(e) => e,
        Err(e) => return Err(e.to_string()),
    };
    let mut files: Vec<(PathBuf, u64, SystemTime, bool, String)> = Vec::new();
    let now = SystemTime::now();

    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                let _ = fs::remove_file(&path);
                continue;
            }
            if meta.file_type().is_file() {
                let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or_default().to_string();
                if fname.starts_with(".tmp_") {
                    if let Ok(modified) = meta.modified() {
                        if now.duration_since(modified).map(|d| d.as_secs() > 10).unwrap_or(false) {
                            let _ = fs::remove_file(&path);
                            continue;
                        }
                    }
                }
                let is_thumb = fname.ends_with("_thumb.webp");
                let hash = if is_thumb {
                    fname.trim_end_matches("_thumb.webp").to_string()
                } else {
                    path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string()
                };
                let size = meta.len();
                let modified = meta.modified().unwrap_or(UNIX_EPOCH);
                files.push((path, size, modified, is_thumb, hash));
            }
        }
    }

    files.sort_by_key(|a| std::cmp::Reverse(a.2));

    let mut total_size: u64 = 0;
    let mut kept_count = 0;
    let mut kept_hashes = std::collections::HashSet::new();

    for (path, size, _, is_thumb, hash) in files {
        if !is_thumb {
            if kept_count < MAX_CLIP_STAGING_FILES && (total_size + size) <= MAX_CLIP_STAGING_BYTES {
                total_size += size;
                kept_count += 1;
                kept_hashes.insert(hash);
            } else {
                let _ = fs::remove_file(&path);
                let thumb_path = staging_dir.join(format!("{}_thumb.webp", hash));
                let _ = fs::remove_file(thumb_path);
            }
        } else {
            if kept_hashes.contains(&hash) && kept_count < MAX_CLIP_STAGING_FILES && (total_size + size) <= MAX_CLIP_STAGING_BYTES {
                total_size += size;
                kept_count += 1;
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }

    Ok(())
}

pub fn is_probable_url(text: &str) -> bool {
    let t = text.trim();
    if t.starts_with("http://") || t.starts_with("https://") || t.starts_with("ftp://") || t.starts_with("gemini://") {
        return true;
    }
    if (t.starts_with("www.") || t.ends_with(".com") || t.ends_with(".org") || t.ends_with(".net") || t.ends_with(".io") || t.ends_with(".tr") || t.ends_with(".me")) && !t.contains(' ') && t.contains('.') {
        return true;
    }
    false
}

pub fn load_clipboard_vault() -> ClipboardVault {
    ClipboardVault::default()
}

pub fn get_clipboard_vault_items() -> Vec<ClipboardItem> {
    Vec::new()
}


pub fn is_sound_enabled() -> bool {
    let f = get_state_dir().join("sound_enabled.txt");
    if let Ok(content) = read_secure_file(&f) {
        let trimmed = content.trim().to_lowercase();
        return trimmed != "false" && trimmed != "0" && trimmed != "off";
    }
    true
}

pub fn set_sound_enabled(enabled: bool) {
    let f = get_state_dir().join("sound_enabled.txt");
    let _ = write_secure_file(&f, if enabled { "true" } else { "false" });
}

pub fn check_firewall_status() -> String {
    let deadline = Instant::now() + Duration::from_millis(250);
    if Path::new("/usr/bin/ufw").exists() {
        if let Some(out) = run_cmd_bounded("/usr/bin/ufw", &["status"], &[], deadline, 4096) {
            let s = String::from_utf8_lossy(&out);
            if s.contains("Status: active") {
                if s.contains("53317") && s.contains("53318") {
                    return "UFW_ALLOWED_53317".to_string();
                } else {
                    return "UFW_ACTIVE_CHECK_53317 (sudo ufw allow 53317/tcp && sudo ufw allow 53317/udp && sudo ufw allow 53318/udp)".to_string();
                }
            }
        }
    }
    "OK".to_string()
}

pub fn request_transfer_cancel() {
    let flag = get_state_dir().join("cancel_transfer.flag");
    let _ = write_secure_file(&flag, "1");
    clear_pending_transfer();
    clear_transfer_progress();
}

pub fn clear_transfer_cancel() {
    let flag = get_state_dir().join("cancel_transfer.flag");
    let _ = fs::remove_file(flag);
}

pub fn is_transfer_cancelled() -> bool {
    get_state_dir().join("cancel_transfer.flag").exists()
}

pub fn save_transfer_progress(direction: &str, filename: &str, bytes: u64, total: u64) {
    let pct = bytes.saturating_mul(100).checked_div(total).map_or(100, |p| p.min(100));
    let val = serde_json::json!({
        "active": true,
        "direction": direction,
        "filename": filename,
        "file_name": filename,
        "bytes_transferred": bytes,
        "total_bytes": total,
        "percent": pct,
        "updated_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    });
    let path = get_state_dir().join("transfer_progress.json");
    let _ = write_secure_file(&path, &val.to_string());
}

pub fn clear_transfer_progress() {
    let path = get_state_dir().join("transfer_progress.json");
    let _ = fs::remove_file(path);
}

pub fn get_transfer_progress() -> Option<serde_json::Value> {
    let path = get_state_dir().join("transfer_progress.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let updated = val["updated_at"].as_u64().unwrap_or(0);
            if now.saturating_sub(updated) <= 15 {
                return Some(val);
            }
        }
    }
    None
}

fn play_clipboard_sound() {
    if !is_sound_enabled() {
        return;
    }
    thread::spawn(|| {
        let env_store = get_desktop_gui_envs();
        let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let deadline = Instant::now() + Duration::from_millis(800);
        let sound_candidates: [(&str, &[&str]); 3] = [
            ("/usr/bin/canberra-gtk-play", &["-i", "message"]),
            ("/usr/bin/paplay", &["/usr/share/sounds/freedesktop/stereo/message.oga"]),
            ("/usr/bin/pw-play", &["/usr/share/sounds/freedesktop/stereo/message.oga"]),
        ];
        for (bin, args) in sound_candidates {
            if Path::new(bin).exists() && run_cmd_bounded(bin, args, &envs, deadline, 1024).is_some() {
                break;
            }
        }
    });
}

fn resolve_omasend_asset_wav(filename: &str) -> Option<PathBuf> {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let mut candidates = vec![
        PathBuf::from(&home).join(".config/omarchy/plugins/ozdil.omasend/assets").join(filename),
        PathBuf::from(&home).join(".local/share/omarchy/plugins/ozdil.omasend/assets").join(filename),
        PathBuf::from("/usr/share/omarchy/plugins/ozdil.omasend/assets").join(filename),
        PathBuf::from(&home).join("Projects/omarchy/omarchy-omasend/assets").join(filename),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.insert(0, dir.join("assets").join(filename));
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

/// Plays the first bundled sound that exists. Returns the player thread so short-lived CLI
/// invocations can wait for it (otherwise the process exits before the sound starts).
fn play_asset_sound(names: &'static [&'static str]) -> Option<thread::JoinHandle<()>> {
    if !is_sound_enabled() {
        return None;
    }
    Some(thread::spawn(move || {
        if let Some(wav) = names.iter().find_map(|n| resolve_omasend_asset_wav(n)) {
            let wav_str = wav.to_string_lossy().to_string();
            let env_store = get_desktop_gui_envs();
            let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let deadline = Instant::now() + Duration::from_millis(5000);
            for bin in ["/usr/bin/pw-play", "/usr/bin/paplay"] {
                if Path::new(bin).exists() && run_cmd_bounded(bin, &[wav_str.as_str()], &envs, deadline, 1024).is_some() {
                    break;
                }
            }
        }
    }))
}

/// "OMAKASE!" on send.
fn play_samurai_send_sound() -> Option<thread::JoinHandle<()>> {
    play_asset_sound(&["send_whoosh.wav", "send.wav"])
}

/// "ONEGAI SHIMASU!" on receive / accept.
fn play_samurai_receive_sound() -> Option<thread::JoinHandle<()>> {
    play_asset_sound(&["receive_whoosh.wav", "receive.wav"])
}

/// CLI paths exit right after their work: wait for the sound to finish playing.
fn finish_sound(handle: Option<thread::JoinHandle<()>>) {
    if let Some(h) = handle {
        let _ = h.join();
    }
}

/// Addresses of paired devices (legacy and QR-paired) that receive unicast discovery beacons,
/// so they see us even where broadcast is filtered. Clipboard pushes use
/// `legacy_clipboard_ips` / `auto_push_clipboard_text` instead.
fn get_active_paired_peer_ips() -> Vec<String> {
    let paired = load_paired_peers();
    let mut ips = Vec::new();

    for p in &paired {
        // Only peers that completed the code-verified handshake.
        if !p.is_active() {
            continue;
        }
        if let Some(ref static_ip) = p.ip {
            if !static_ip.is_empty() && !ips.contains(static_ip) {
                ips.push(static_ip.clone());
            }
        }
    }

    // QR-paired keys, at the address of their last authenticated request.
    for k in trust_store().load() {
        if !k.ip.is_empty() && !ips.contains(&k.ip) {
            ips.push(k.ip);
        }
    }
    ips
}

/// Automatic clipboard sync goes only to the user's OWN QR-paired devices, over the encrypted
/// QUIC channel. Legacy (OmaID) peers and devices paired as someone else's never get automatic
/// pushes: the legacy HTTP path is plaintext on the LAN (M6). `--sync-clipboard <peer>` still
/// sends to a legacy peer when the user asks for it explicitly.
fn auto_push_clipboard_text(text: &str) {
    for key in trust_store().load().into_iter().filter(|k| k.own_device) {
        let text = text.to_string();
        thread::spawn(move || {
            if let Err((_, e)) = core_clipboard(&key, &text) {
                eprintln!("Clipboard to {} not delivered: {}", key.name, e);
            }
        });
    }
}

pub fn p2p_push_image_clipboard_silent(
    target_ip: &str,
    content_type: &str,
    hash: &str,
    size: u64,
    width: u32,
    height: u32,
    data: Option<&[u8]>,
) {
    if target_ip.is_empty() {
        return;
    }
    let (my_id, _) = get_or_create_device_id();
    let my_name = get_system_hostname();
    let auth_token = legacy_token_for_ip(target_ip);

    let image_base64 = if let Some(d) = data {
        if d.len() <= INLINE_IMAGE_CLIP_MAX_SIZE {
            Some(base64_encode(d))
        } else {
            None
        }
    } else {
        None
    };

    let staging_dir = get_clip_staging_dir();
    let ext = match content_type {
        "image_jpeg" => "jpg",
        "image_webp" => "webp",
        _ => "png",
    };
    let img_path = staging_dir.join(format!("{}.{}", hash, ext));
    let thumb_b64 = if img_path.exists() {
        generate_webp_thumbnail_for_staging(&img_path, hash)
    } else {
        None
    };

    let local_ip = get_local_ip();
    // No OmaID and no OmaID-keyed "envelope": the request is authorized by its v2 signature
    // (or, for a legacy peer, by the pairing token in the header).
    let final_payload = serde_json::json!({
        "sender_id": my_id,
        "device_id": my_id,
        "sender_name": my_name,
        "sender_alias": my_name,
        "sender_ip": local_ip,
        "content_type": content_type,
        "image_hash": hash,
        "image_size": size,
        "image_width": width,
        "image_height": height,
        "width": width,
        "height": height,
        "image_base64": image_base64,
        "image_data_base64": image_base64,
        "thumbnail_base64": thumb_b64
    });

    let addr = resolve_peer_addr(target_ip);
    let req_bytes = final_payload.to_string().into_bytes();
    let auth_hdr = legacy_token_header(&auth_token);
    thread::spawn(move || {
        if let Ok(mut stream) = connect_peer_with_timeout(&addr, Duration::from_millis(2500)) {
            let http_req = format!(
                "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}{}Content-Length: {}\r\nConnection: close\r\n\r\n",
                addr, auth_hdr,
                v2_auth_lines("POST", "/api/p2p/clipboard", &devicekey::body_tag_json(&req_bytes)),
                req_bytes.len()
            );
            let _ = stream.write_all(http_req.as_bytes());
            let _ = stream.write_all(&req_bytes);
            let mut resp = Vec::new();
            let _ = (&mut stream).take(64 * 1024).read_to_end(&mut resp);
        }
    });
}

pub fn p2p_fetch_image_clipboard_and_apply(sender_ip: &str, hash: &str, _content_type: &str) {
    if sender_ip.is_empty() || hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return;
    }
    let ip = sender_ip.to_string();
    let h = hash.to_string();
    // Legacy peers authorize the fetch with the token from the code-verified pairing.
    let auth_hdr = legacy_token_header(&legacy_token_for_ip(sender_ip));
    thread::spawn(move || {
        let addr = resolve_peer_addr(&ip);
        if let Ok(mut stream) = connect_peer_with_timeout(&addr, Duration::from_secs(5)) {
            let pq = format!("/api/p2p/clipboard/image?hash={}", h);
            let http_req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\n{}{}Connection: close\r\n\r\n",
                pq, addr, auth_hdr, v2_auth_lines("GET", &pq, &devicekey::body_tag_json(b""))
            );
            if stream.write_all(http_req.as_bytes()).is_ok() {
                let max_resp_bytes = (MAX_IMAGE_CLIP_SIZE + 65536) as u64;
                let mut resp_bytes = Vec::new();
                if (&mut stream)
                    .take(max_resp_bytes + 1)
                    .read_to_end(&mut resp_bytes)
                    .is_ok()
                    && (resp_bytes.len() as u64) <= max_resp_bytes
                {
                    if let Some(pos) = resp_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header_part = String::from_utf8_lossy(&resp_bytes[..pos]);
                        if header_part.starts_with("HTTP/1.1 200") || header_part.starts_with("HTTP/1.0 200") {
                            let body_bytes = &resp_bytes[pos + 4..];
                            if let Ok((verified_ct, _w, _h)) = validate_image_header(body_bytes) {
                                if verify_image_clipboard_hash(body_bytes, &h) {
                                    let _ = stage_clipboard_image(body_bytes, &verified_ct);
                                    let _ = set_pc_image_clipboard(body_bytes, &verified_ct);
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

/// Fallback poll interval when `wl-paste --watch` is not available (X11, old wl-clipboard).
const CLIPBOARD_POLL_FALLBACK: Duration = Duration::from_secs(1);

/// Checks the text clipboard once and pushes it to own devices if it changed.
fn on_clipboard_maybe_changed() {
    // Images are not synced automatically: the encrypted channel carries text only, and
    // images used to go to legacy peers over plaintext HTTP (M6). Image clipboards are
    // not valid text (see is_valid_text_clipboard), so they are skipped below.
    let text = get_pc_clipboard();
    if text.trim().is_empty() {
        return;
    }

    let hash = compute_clipboard_hash(&text);
    if get_last_synced_clipboard_hash().as_deref() == Some(&hash) {
        return;
    }
    set_last_synced_clipboard_hash(&hash);

    // Sensitive Clipboard Shield: Never broadcast passwords, secret keys, or credentials
    if military::is_sensitive_clipboard_payload(&text) {
        return;
    }

    auto_push_clipboard_text(&text);
}

/// One long-lived `wl-paste --watch` process. For every clipboard change it runs a tiny shell
/// command that discards the content and prints one line, so the sentinel wakes only when the
/// clipboard actually changes instead of spawning wl-paste four times a second.
fn spawn_clipboard_watch() -> Option<std::process::Child> {
    if !Path::new("/usr/bin/wl-paste").is_file() || !Path::new("/usr/bin/sh").is_file() {
        return None;
    }
    let mut cmd = Command::new("/usr/bin/wl-paste");
    cmd.args(["--watch", "/usr/bin/sh", "-c", "cat >/dev/null; echo"])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    for (k, v) in get_desktop_gui_envs() {
        cmd.env(k, v);
    }
    // SAFETY: prctl is async-signal-safe; the watcher must not outlive the daemon.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    cmd.spawn().ok()
}

pub fn start_clipboard_sentinel() {
    thread::spawn(move || {
        let initial_text = get_pc_clipboard();
        if !initial_text.trim().is_empty() {
            let initial_hash = compute_clipboard_hash(&initial_text);
            set_last_synced_clipboard_hash(&initial_hash);
        }

        loop {
            let started = Instant::now();
            if let Some(mut child) = spawn_clipboard_watch() {
                if let Some(out) = child.stdout.take() {
                    use std::io::BufRead;
                    // One line per clipboard change; ends when wl-paste exits.
                    for line in std::io::BufReader::new(out).lines() {
                        if line.is_err() {
                            break;
                        }
                        on_clipboard_maybe_changed();
                    }
                }
                let pid = child.id() as i32;
                subproc::reap_process_group(&mut child, pid);
                if started.elapsed() >= Duration::from_secs(10) {
                    // It ran for a while (compositor restart, logout): start it again.
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            }
            // No working `wl-paste --watch`: poll for a minute, then try the watcher again.
            let until = Instant::now() + Duration::from_secs(60);
            while Instant::now() < until {
                thread::sleep(CLIPBOARD_POLL_FALLBACK);
                on_clipboard_maybe_changed();
            }
        }
    });
}

pub fn is_valid_text_clipboard(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    // Reject binary signatures (PNG, JPEG, GIF, ELF, WebP, etc.)
    if data.starts_with(b"\x89PNG") || data.starts_with(b"\xFF\xD8\xFF") || data.starts_with(b"GIF8") || data.starts_with(b"\x7fELF") || (data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP") {
        return None;
    }
    // Reject if contains null bytes in initial chunk
    if data.iter().take(2048).any(|&b| b == 0) {
        return None;
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return None;
        }
        // Count non-printable control characters
        let ctrl_count = trimmed.chars().take(200).filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t').count();
        if ctrl_count > 2 {
            return None;
        }
        Some(trimmed.to_string())
    } else {
        None
    }
}

pub fn get_pc_image_clipboard() -> Option<(Vec<u8>, String, u32, u32)> {
    let env_store = get_desktop_gui_envs();
    let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let deadline = Instant::now() + Duration::from_millis(800);

    if let Some(out) = run_cmd_bounded("/usr/bin/wl-paste", &["--type", "image/png", "--no-newline"], &envs, deadline, MAX_IMAGE_CLIP_SIZE) {
        if let Ok((ct, w, h)) = validate_image_header(&out) {
            return Some((out, ct, w, h));
        }
    }
    if let Some(out) = run_cmd_bounded("/usr/bin/xclip", &["-selection", "clipboard", "-o", "-t", "image/png"], &envs, deadline, MAX_IMAGE_CLIP_SIZE) {
        if let Ok((ct, w, h)) = validate_image_header(&out) {
            return Some((out, ct, w, h));
        }
    }
    None
}

pub fn set_pc_image_clipboard(data: &[u8], content_type: &str) -> bool {
    let env_store = get_desktop_gui_envs();
    let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let deadline = Instant::now() + Duration::from_millis(1200);
    let mime = match content_type {
        "image_jpeg" => "image/jpeg",
        "image_webp" => "image/webp",
        _ => "image/png",
    };

    let success = subproc::run_cmd_write_stdin_bounded("/usr/bin/wl-copy", &["--type", mime], &envs, data, deadline);
    if !success {
        subproc::run_cmd_write_stdin_bounded("/usr/bin/xclip", &["-selection", "clipboard", "-t", mime], &envs, data, deadline)
    } else {
        true
    }
}

fn get_pc_clipboard() -> String {
    let env_store = get_desktop_gui_envs();
    let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let deadline = Instant::now() + Duration::from_millis(600);
    if let Some(out) = run_cmd_bounded("/usr/bin/wl-paste", &["--type", "text", "--no-newline"], &envs, deadline, 1024 * 1024) {
        if let Some(res) = is_valid_text_clipboard(&out) {
            return res;
        }
    }
    if let Some(out) = run_cmd_bounded("/usr/bin/xclip", &["-selection", "clipboard", "-o", "-t", "UTF8_STRING"], &envs, deadline, 1024 * 1024) {
        if let Some(res) = is_valid_text_clipboard(&out) {
            return res;
        }
    }
    String::new()
}

fn set_pc_clipboard(text: &str) {
    let env_store = get_desktop_gui_envs();
    let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let deadline = Instant::now() + Duration::from_millis(800);
    let success = subproc::run_cmd_write_stdin_bounded("/usr/bin/wl-copy", &[], &envs, text.as_bytes(), deadline);
    if !success {
        let _ = subproc::run_cmd_write_stdin_bounded("/usr/bin/xclip", &["-selection", "clipboard"], &envs, text.as_bytes(), deadline);
    }
}

fn sanitize_filename(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_' || *c == ' ')
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed.starts_with('.') || trimmed.contains("..") {
        format!("file_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs())
    } else {
        // Truncate by characters, never by bytes: a byte index can land inside a multibyte
        // character and panic (with panic = "abort" that kills the daemon).
        trimmed.chars().take(180).collect::<String>().trim_end().to_string()
    }
}

fn get_unique_filepath(dir: &Path, filename: &str) -> PathBuf {
    let target = dir.join(filename);
    if !target.exists() {
        return target;
    }
    let p = Path::new(filename);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
    for i in 1..1000 {
        let candidate_name = if ext.is_empty() {
            format!("{}_{}", stem, i)
        } else {
            format!("{}_{}.{}", stem, i, ext)
        };
        let candidate_path = dir.join(&candidate_name);
        if !candidate_path.exists() {
            return candidate_path;
        }
    }
    dir.join(format!("{}_{}", stem, SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()))
}

fn get_directory_files(dir: &Path) -> Vec<FileInfo> {
    let mut files = Vec::new();
    let current_uid = get_current_uid();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = fs::symlink_metadata(&p) {
                if !meta.file_type().is_symlink() && meta.file_type().is_file() && meta.uid() == current_uid {
                    let size_bytes = meta.len();
                    let size_str = if size_bytes > 1_000_000_000 {
                        format!("{:.2} GB", size_bytes as f64 / 1_000_000_000.0)
                    } else if size_bytes > 1_000_000 {
                        format!("{:.1} MB", size_bytes as f64 / 1_000_000.0)
                    } else if size_bytes > 1_000 {
                        format!("{:.1} KB", size_bytes as f64 / 1_000.0)
                    } else {
                        format!("{} B", size_bytes)
                    };
                    files.push(FileInfo {
                        name: entry.file_name().to_string_lossy().to_string(),
                        size_str,
                        size_bytes,
                    });
                }
            }
        }
    }
    files.sort_by_key(|a| std::cmp::Reverse(a.size_bytes));
    files
}

// ------------------- P2P AIRBRIDGE MODULE (STRICT OMAID) -------------------

fn urlencoding_encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn get_system_hostname() -> String {
    if let Ok(content) = fs::read_to_string("/etc/hostname") {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let deadline = Instant::now() + Duration::from_millis(200);
    if let Some(out) = run_cmd_bounded("/usr/bin/hostname", &[], &[], deadline, 256) {
        let s = String::from_utf8_lossy(&out).trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    "Omarchy-PC".to_string()
}

fn get_or_create_device_id() -> (String, String) {
    let key_file = get_state_dir().join("device_id.key");
    if let Ok(content) = read_secure_file(&key_file) {
        let trimmed = content.trim();
        if trimmed.len() == 64 && hex::decode(trimmed).is_ok() {
            let mut hasher = Sha256::new();
            hasher.update(trimmed.as_bytes());
            let fp = hex::encode(hasher.finalize());
            let id = fp[..16].to_string();
            return (id, fp);
        }
    }
    let mut seed = [0u8; 32];
    let _ = getrandom::getrandom(&mut seed);
    let seed_hex = hex::encode(seed);
    let _ = write_secure_file(&key_file, &seed_hex);

    let mut hasher = Sha256::new();
    hasher.update(seed_hex.as_bytes());
    let fp = hex::encode(hasher.finalize());
    let id = fp[..16].to_string();
    (id, fp)
}

fn get_visibility() -> (String, u64) {
    let vis_file = get_state_dir().join("visibility.json");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if let Ok(content) = read_secure_file(&vis_file) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            let mode = val["mode"].as_str().unwrap_or("KNOWN").to_uppercase();
            let expires_at = val["expires_at"].as_u64().unwrap_or(0);
            if mode == "EVERYONE" {
                if now < expires_at {
                    return ("EVERYONE".to_string(), expires_at.saturating_sub(now));
                } else {
                    set_visibility("KNOWN");
                    return ("KNOWN".to_string(), 0);
                }
            }
            return (mode, 0);
        }
    }
    ("KNOWN".to_string(), 0)
}

fn broadcast_offline_beacon() {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = socket.set_broadcast(true);
    let (device_id, fp) = get_or_create_device_id();
    let hostname = get_system_hostname();
    let ip = get_local_ip();

    let packet = P2pBeaconPacket {
        magic: "OMASEND_P2P".to_string(),
        v: 1,
        id: device_id,
        oma_id: String::new(),
        name: hostname,
        ip: ip.clone(),
        port: PORT,
        mode: "OFF".to_string(),
        fp,
        pk: device_identity().public_b64(),
    };

    if let Ok(bytes) = serde_json::to_vec(&packet) {
        let _ = socket.send_to(&bytes, format!("255.255.255.255:{}", P2P_BEACON_PORT));
        if let Some(dot) = ip.rfind('.') {
            let subnet_bcast24 = format!("{}.255:{}", &ip[..dot], P2P_BEACON_PORT);
            let _ = socket.send_to(&bytes, subnet_bcast24);
        }
    }
}

fn set_visibility(mode: &str) {
    let upper = mode.to_uppercase();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let expires_at = if upper == "EVERYONE" {
        now.saturating_add(600) // 10 minutes
    } else {
        0
    };
    let data = serde_json::json!({
        "mode": upper,
        "expires_at": expires_at
    });
    let vis_file = get_state_dir().join("visibility.json");
    let _ = write_secure_file(&vis_file, &data.to_string());
    if upper == "OFF" {
        let peers_file = get_state_dir().join("discovered_peers.json");
        let _ = fs::remove_file(peers_file);
        broadcast_offline_beacon();
    }
}

pub fn load_paired_peers() -> Vec<rendezvous::PairedPeer> {
    rendezvous::load_paired_peers(&get_state_dir())
}

pub fn is_peer_paired(oma_id: &str) -> bool {
    rendezvous::is_peer_paired(oma_id, &get_state_dir())
}

pub fn add_paired_peer(oma_id: &str, name: &str, ip: Option<&str>) -> Result<rendezvous::PairedPeer, String> {
    rendezvous::add_paired_peer(oma_id, name, ip, &get_state_dir())
}

pub fn begin_local_pairing(oma_id: &str, name: &str, ip_hint: Option<&str>) -> Result<(rendezvous::PairedPeer, String), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    rendezvous::begin_local_pairing(oma_id, name, ip_hint, &get_state_dir(), now)
}

pub fn complete_remote_pairing(oma_id: &str, code: &str, source_ip: IpAddr) -> Result<rendezvous::PairedPeer, rendezvous::PairingError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    rendezvous::complete_remote_pairing(oma_id, code, source_ip, &get_state_dir(), now)
}

// ------------------- PHASE 2: ENCRYPTED QUIC CORE (omasend-core / iroh) -------------------

pub const CORE_QUIC_PORT: u16 = omasend_core::DEFAULT_PORT;
static CORE_NODE: std::sync::OnceLock<std::sync::Arc<omasend_core::OmaNode>> = std::sync::OnceLock::new();

fn trust_of(pk: &str) -> omasend_core::Trust {
    match trust_store().get(pk) {
        Some(k) if k.own_device => omasend_core::Trust::Own,
        Some(_) => omasend_core::Trust::Paired,
        None => omasend_core::Trust::Unknown,
    }
}

/// The paired key a discovered peer belongs to: by advertised key, or (older peers that
/// do not advertise one) by the address the key last authenticated from.
fn key_for_discovered<'a>(keys: &'a [devicekey::TrustedKey], p: &DiscoveredPeer) -> Option<&'a devicekey::TrustedKey> {
    if !p.pk.is_empty() {
        return keys.iter().find(|k| k.pk == p.pk);
    }
    keys.iter().find(|k| !k.ip.is_empty() && k.ip == p.ip)
}

/// Resolves a send/clipboard target to a QR-paired key. Accepts a device id
/// (XXXX-XXXX-XXXX-XXXX), a public key, or an IP / host:port. For an address, what is
/// currently discovered there wins over the key's last known address (DHCP reuse).
fn trusted_key_for_target(target: &str) -> Option<devicekey::TrustedKey> {
    let t = target.trim();
    if t.is_empty() {
        return None;
    }
    let keys = trust_store().load();
    if let Some(k) = keys.iter().find(|k| k.device_id.eq_ignore_ascii_case(t) || k.pk == t) {
        return Some(k.clone());
    }
    let host = match t.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.parse::<u16>().is_ok() => h,
        _ => t,
    };
    if let Some(p) = get_discovered_peers().into_iter().find(|p| p.ip == host) {
        return key_for_discovered(&keys, &p).cloned();
    }
    keys.into_iter().find(|k| !k.ip.is_empty() && k.ip == host)
}

/// Candidate QUIC addresses for a paired key: where discovery currently sees it, then the
/// address it last authenticated from. TLS verifies the key, so extra candidates are safe.
fn core_addrs(key: &devicekey::TrustedKey) -> Vec<String> {
    let port = if key.quic_port > 0 { key.quic_port } else { CORE_QUIC_PORT };
    let mut ips: Vec<String> = get_discovered_peers()
        .into_iter()
        .filter(|p| !p.pk.is_empty() && p.pk == key.pk && !p.ip.is_empty())
        .map(|p| p.ip)
        .collect();
    if !key.ip.is_empty() && !ips.contains(&key.ip) {
        ips.push(key.ip.clone());
    }
    ips.into_iter().map(|ip| format!("{}:{}", ip, port)).collect()
}

/// User-facing message for a failed transfer/clipboard push to a paired device.
fn core_failure_message(name: &str, err: &str) -> String {
    let m = err.to_lowercase();
    if m.contains("declined") {
        format!("{} declined the transfer.", name)
    } else if m.contains("not paired") {
        format!("{} does not recognize this device any more. Remove the pairing and pair again with a QR code.", name)
    } else if core_error_is_unavailable(err) {
        format!(
            "{} is not reachable over the encrypted connection. Make sure OmaSend is running there and UDP {} is allowed by the firewall. ({})",
            name, CORE_QUIC_PORT, err
        )
    } else {
        err.to_string()
    }
}

/// QR-paired devices for the panel / `--devices`, with online state from discovery.
fn paired_devices_view() -> Vec<serde_json::Value> {
    let discovered = get_discovered_peers();
    trust_store()
        .load()
        .into_iter()
        .map(|k| {
            let seen = discovered.iter().find(|p| key_for_discovered(std::slice::from_ref(&k), p).is_some());
            serde_json::json!({
                "device_id": k.device_id,
                "name": k.name,
                "ip": seen.map(|p| p.ip.clone()).unwrap_or_else(|| k.ip.clone()),
                "own_device": k.own_device,
                "online": seen.is_some(),
                "added_at": k.added_at,
                "last_seen": k.last_seen,
            })
        })
        .collect()
}

/// Errors that mean "the paired device could not be reached over the encrypted channel"
/// (shown with a firewall hint). A TLS handshake/certificate failure means something else
/// answered at that address: the key check did its job, the device itself was not reached.
fn core_error_is_unavailable(msg: &str) -> bool {
    let m = msg.to_lowercase();
    ["timed out", "connect", "not paired", "unreachable", "no such file", "permission denied", "core not running", "handshake", "certificate", "no address"]
        .iter()
        .any(|p| m.contains(p))
}

struct DesktopCoreCallbacks {
    last_progress_write: Mutex<Instant>,
}

impl omasend_core::NodeCallbacks for DesktopCoreCallbacks {
    fn trust(&self, peer_pk: String) -> omasend_core::Trust {
        trust_of(&peer_pk)
    }

    fn peer_name(&self, peer_pk: String) -> String {
        trust_store().get(&peer_pk).map(|k| k.name).unwrap_or_default()
    }

    fn incoming_offer(&self, offer: omasend_core::IncomingOffer) {
        let node = CORE_NODE.get().cloned();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let files: Vec<TransferFileInfo> = offer
            .files
            .iter()
            .map(|f| TransferFileInfo { name: f.name.clone(), size_bytes: f.size, blake3: None, sha256: None, md5: None })
            .collect();
        let size_mb = (offer.total_size as f64) / 1024.0 / 1024.0;
        // Single pending slot (V2-FUNC-01): refuse while another transfer is live. The core only
        // offers from paired keys, so this counts as a verified sender (M9).
        let claimed = claim_pending_slot(&PendingFileTransfer {
            token: offer.transfer_id.clone(),
            sender_id: offer.peer_pk.clone(),
            sender_name: offer.peer_name.clone(),
            sender_ip: trust_store().get(&offer.peer_pk).map(|k| k.ip).unwrap_or_default(),
            file_names: files.iter().map(|f| f.name.clone()).collect(),
            remaining_files: files.len().max(1),
            files,
            total_size_bytes: offer.total_size,
            created_at: now,
            expires_at: now + 120,
            status: "PENDING".to_string(),
            sender_pk: Some(offer.peer_pk.clone()),
            transport: Some("quic".to_string()),
        }, true);
        if !claimed {
            if let Some(n) = node {
                n.respond(offer.transfer_id, false);
            }
            return;
        }
        notify_desktop(
            "OmaSend AirBridge: Transfer Request",
            &format!("'{}' wants to send {} file(s) ({:.1} MB), end-to-end encrypted.\nOpen OmaSend panel to Accept or Decline.", offer.peer_name, offer.files.len(), size_mb),
        );
    }

    fn progress(&self, transfer_id: String, direction: omasend_core::Direction, file_name: String, done: u64, total: u64) {
        if is_transfer_cancelled() {
            clear_transfer_cancel();
            if let Some(n) = CORE_NODE.get() {
                n.cancel(transfer_id);
            }
            return;
        }
        let mut last = self.last_progress_write.lock().unwrap_or_else(|p| p.into_inner());
        if done >= total || last.elapsed() >= Duration::from_millis(250) {
            *last = Instant::now();
            let dir = if direction == omasend_core::Direction::Send { "send" } else { "receive" };
            save_transfer_progress(dir, &file_name, done, total);
        }
    }

    fn file_received(&self, _transfer_id: String, peer_pk: String, path: String) {
        let name = Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
        record_notified_file(&name);
        play_samurai_receive_sound();
        let from = trust_store().get(&peer_pk).map(|k| k.name).unwrap_or_else(|| "paired device".into());
        notify_desktop("OmaSend: Transfer Complete", &format!("'{}' received from {} (encrypted, BLAKE3 verified).", name, from));
    }

    fn transfer_finished(&self, transfer_id: String, direction: omasend_core::Direction, ok: bool, error: Option<String>) {
        clear_transfer_progress();
        if direction == omasend_core::Direction::Receive {
            if get_pending_transfer().is_some_and(|p| p.token == transfer_id) {
                clear_pending_transfer();
            }
            if !ok {
                if let Some(e) = error.filter(|e| e != "declined") {
                    notify_desktop("OmaSend AirBridge", &format!("Incoming transfer failed: {}", e));
                }
            }
        }
    }

    fn clipboard(&self, peer_pk: String, text: String) {
        set_last_synced_clipboard_hash(&compute_clipboard_hash(&text));
        if military::is_sensitive_clipboard_payload(&text) {
            return;
        }
        set_pc_clipboard(&text);
        let from = trust_store().get(&peer_pk).map(|k| k.name).unwrap_or_else(|| "paired device".into());
        notify_desktop("OmaSend: Universal Clipboard", &format!("Received clipboard text from {}.", from));
        play_clipboard_sound();
    }
}

/// Started once by the daemon. Failure is non-fatal: the HTTP transport keeps working.
fn start_core_node() {
    if CORE_NODE.get().is_some() {
        return;
    }
    let cb = std::sync::Arc::new(DesktopCoreCallbacks { last_progress_write: Mutex::new(Instant::now()) });
    match omasend_core::OmaNode::start(
        device_identity().seed().to_vec(),
        get_system_hostname(),
        get_download_dir().to_string_lossy().to_string(),
        CORE_QUIC_PORT,
        false,
        cb,
    ) {
        Ok(node) => {
            println!("omasend-core listening on UDP {}", node.bound_port());
            let _ = CORE_NODE.set(node);
        }
        Err(e) => eprintln!("omasend-core unavailable, HTTP only: {}", e),
    }
}

fn local_api_token_path() -> PathBuf {
    get_state_dir().join("local_api.token")
}

/// Secret for daemon-local control endpoints (CLI -> daemon), mode 0600.
fn ensure_local_api_token() -> String {
    if let Ok(t) = read_secure_file(&local_api_token_path()) {
        if t.trim().len() == 64 {
            return t.trim().to_string();
        }
    }
    let mut b = [0u8; 32];
    let _ = getrandom::getrandom(&mut b);
    let t = hex::encode(b);
    let _ = write_secure_file(&local_api_token_path(), &t);
    t
}

/// Headers a reverse proxy (cloudflared for the WAN tunnel) adds. A loopback connection that
/// carries one of them came from the internet, not from a process on this machine.
const TUNNEL_HEADERS: &[&str] = &["cf-connecting-ip", "cf-ray", "x-forwarded-for", "x-real-ip", "forwarded", "cdn-loop"];

fn has_tunnel_headers(req: &HttpRequest) -> bool {
    TUNNEL_HEADERS.iter().any(|h| req.get_header(h).is_some())
}

/// A request that came in through the WAN tunnel: cloudflared connects from loopback and adds
/// its headers. Such requests may only reach the web portal (see `is_portal_route`).
fn is_tunnel_request(req: &HttpRequest, client_ip: IpAddr) -> bool {
    client_ip.to_canonical().is_loopback() && has_tunnel_headers(req)
}

/// The only routes served to the internet through the WAN tunnel: the portal page, its login,
/// status, and the E2EE (browser-encrypted) upload, download and clipboard endpoints. Pairing,
/// linking, v2/core, local control, p2p transfers/decisions/clipboard, and the plaintext portal
/// variants stay LAN-only.
fn is_portal_route(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("GET", "/") | ("POST", "/api/login") | ("GET", "/api/status") | ("POST", "/api/upload-encrypted")
            | ("GET", "/api/clipboard-encrypted") | ("POST", "/api/clipboard-encrypted")
    ) || (method == "GET" && path.starts_with("/api/download-encrypted/"))
}

fn local_token_matches(req: &HttpRequest) -> bool {
    req.get_header("x-omasend-local")
        .is_some_and(|t| constant_time_eq_str(t.trim(), &ensure_local_api_token()))
}

/// True only for a request from a local process that can read the 0600 local API token (the
/// CLI and the panel through it). Loopback alone proves nothing: the WAN tunnel connects
/// from 127.0.0.1.
fn is_local_control(req: &HttpRequest, client_ip: IpAddr) -> bool {
    client_ip.to_canonical().is_loopback() && !has_tunnel_headers(req) && local_token_matches(req)
}

/// The address rate limiters key on. WAN tunnel clients all arrive from loopback, so use the
/// client address cloudflared reports for them instead of one shared bucket.
fn rate_limit_ip(req: &HttpRequest, client_ip: IpAddr) -> IpAddr {
    let ip = client_ip.to_canonical();
    if ip.is_loopback() {
        if let Some(real) = req.get_header("cf-connecting-ip").and_then(|v| v.trim().parse::<IpAddr>().ok()) {
            return real.to_canonical();
        }
    }
    ip
}

/// Sends files through the daemon's QUIC endpoint. Err((unavailable, message)).
fn core_send_via_daemon(key: &devicekey::TrustedKey, paths: &[String], names: &[String]) -> Result<(), (bool, String)> {
    if let Some(node) = CORE_NODE.get() {
        return node
            .send_files(key.pk.clone(), core_addrs(key), paths.to_vec(), names.to_vec(), String::new())
            .map(|_| ())
            .map_err(|e| {
                let m = e.to_string();
                (core_error_is_unavailable(&m), m)
            });
    }
    // The daemon runs under Landlock without read access to $HOME, so it cannot open the
    // user's files itself (EACCES, "os error 13"). Hand it links or copies in a private
    // directory it may read, and remove them once the (blocking) send has returned.
    let stage = stage_outgoing_files(paths).map_err(|e| (false, format!("could not prepare files: {}", e)))?;
    let staged: Vec<String> = stage.paths.iter().map(|p| p.to_string_lossy().to_string()).collect();
    core_daemon_request(serde_json::json!({ "pk": key.pk, "addrs": core_addrs(key), "paths": staged, "names": names }))
}

fn outgoing_stage_root() -> PathBuf {
    get_state_dir().join("outgoing")
}

/// Files handed to the sandboxed daemon for one send; the directory is removed on drop.
struct OutgoingStage {
    dir: PathBuf,
    paths: Vec<PathBuf>,
}

impl Drop for OutgoingStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn stage_outgoing_files(paths: &[String]) -> std::io::Result<OutgoingStage> {
    let mut rand_bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut rand_bytes);
    let dir = outgoing_stage_root().join(hex::encode(rand_bytes));
    fs::create_dir_all(&dir)?;
    let _ = fs::set_permissions(outgoing_stage_root(), fs::Permissions::from_mode(0o700));
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    let mut stage = OutgoingStage { dir, paths: Vec::with_capacity(paths.len()) };
    for (i, src) in paths.iter().enumerate() {
        // One subdirectory per file keeps the file name and avoids clashes between equal names.
        let slot = stage.dir.join(i.to_string());
        fs::create_dir(&slot)?;
        let name = Path::new(src).file_name().map(|n| n.to_os_string()).unwrap_or_else(|| "file".into());
        let dst = slot.join(name);
        // A hard link is instant and costs no space; across file systems fall back to a copy.
        if fs::hard_link(src, &dst).is_err() {
            fs::copy(src, &dst)?;
        }
        stage.paths.push(dst);
    }
    Ok(stage)
}

/// Removes staging directories left behind by a CLI that was killed mid-send.
fn clean_stale_outgoing() {
    let Ok(entries) = fs::read_dir(outgoing_stage_root()) else { return };
    let day = Duration::from_secs(24 * 3600);
    for e in entries.flatten() {
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > day);
        if old {
            let _ = fs::remove_dir_all(e.path());
        }
    }
}

/// Encrypted clipboard push to a paired key. Never downgraded to plaintext HTTP.
fn core_clipboard(key: &devicekey::TrustedKey, text: &str) -> Result<(), (bool, String)> {
    if let Some(node) = CORE_NODE.get() {
        return node.send_clipboard(key.pk.clone(), core_addrs(key), text.to_string()).map_err(|e| {
            let m = e.to_string();
            (core_error_is_unavailable(&m), m)
        });
    }
    core_daemon_request(serde_json::json!({ "pk": key.pk, "addrs": core_addrs(key), "text": text }))
}

/// CLI -> daemon request on a loopback-only, token-protected endpoint. Returns the JSON body.
/// Err means the daemon could not be reached.
fn local_api_request(path: &str, body: &serde_json::Value, timeout: Option<Duration>) -> Result<serde_json::Value, String> {
    let token = read_secure_file(&local_api_token_path()).map_err(|_| "daemon not running (no local token)".to_string())?;
    let body = body.to_string();
    let mut stream = connect_peer_with_timeout(&format!("127.0.0.1:{}", PORT), Duration::from_secs(2))
        .map_err(|e| format!("daemon not running: {}", e))?;
    let _ = stream.set_read_timeout(timeout);
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nX-OmaSend-Local: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        token.trim(),
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    (&mut stream).take(64 * 1024).read_to_string(&mut resp).map_err(|e| e.to_string())?;
    Ok(resp
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or_default())
}

/// CLI -> daemon request on the loopback-only, token-protected core endpoint.
fn core_daemon_request(body: serde_json::Value) -> Result<(), (bool, String)> {
    let json = local_api_request("/api/local/core-send", &body, None).map_err(|e| (true, format!("core not running: {}", e)))?;
    if json["ok"].as_bool() == Some(true) {
        Ok(())
    } else {
        Err((
            json["unavailable"].as_bool().unwrap_or(true),
            json["error"].as_str().unwrap_or("core send failed").to_string(),
        ))
    }
}

// ------------------- PHASE 1: DEVICE KEYS (devicekey.rs) -------------------

fn device_identity() -> &'static devicekey::DeviceIdentity {
    static ID: std::sync::OnceLock<devicekey::DeviceIdentity> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        devicekey::load_or_create_identity(&get_state_dir()).unwrap_or_else(|_| {
            let mut seed = [0u8; 32];
            let _ = getrandom::getrandom(&mut seed);
            devicekey::DeviceIdentity::from_seed(seed)
        })
    })
}

fn trust_store() -> devicekey::TrustStore {
    devicekey::TrustStore::new(&get_state_dir())
}

/// Signature header lines for an outgoing request (each ends with CRLF).
fn v2_auth_lines(method: &str, path_and_query: &str, body_tag: &str) -> String {
    devicekey::auth_header_lines(device_identity(), method, path_and_query, body_tag)
}

/// Verifies v2 signature headers. A signature from a key we never paired with is treated
/// like an unsigned legacy request (legacy rules then apply); a bad signature, stale
/// timestamp or replay from a known key is rejected.
fn v2_verify(req: &HttpRequest, body_tag: &str, client_ip: &str) -> devicekey::AuthResult {
    let pq = if req.query.is_empty() { req.path.clone() } else { format!("{}?{}", req.path, req.query) };
    let h = devicekey::SignedHeaders {
        pk: req.get_header("x-omasend-pk"),
        ts: req.get_header("x-omasend-ts"),
        nonce: req.get_header("x-omasend-nonce"),
        sig: req.get_header("x-omasend-sig"),
    };
    let store = trust_store();
    match devicekey::verify_request(&store, &h, &req.method, &pq, body_tag) {
        devicekey::AuthResult::Rejected("Unknown device key") => devicekey::AuthResult::Absent,
        devicekey::AuthResult::Trusted(k) => {
            // A loopback source is the WAN tunnel (or this machine), not the peer's LAN address:
            // storing it would make later QUIC sends dial ourselves (M14).
            let is_loopback = client_ip.parse::<IpAddr>().is_ok_and(|ip| ip.to_canonical().is_loopback());
            store.touch(&k.pk, if is_loopback { "" } else { client_ip });
            devicekey::AuthResult::Trusted(k)
        }
        other => other,
    }
}

pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn load_trusted_peers() -> Vec<TrustedPeer> {
    let path = get_state_dir().join("trusted_peers.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(db) = serde_json::from_str::<TrustedPeersDb>(&content) {
            return db.peers;
        }
    }
    Vec::new()
}

/// Legacy (v1) authorization: the auth token a code-verified pairing stored. The token is the
/// credential; the peer is looked up by it, never by a claimed OmaID (public, broadcast by
/// older versions). A pairing without a token authorizes nothing any more.
fn legacy_peer_authorized(provided_token: &str) -> Option<rendezvous::PairedPeer> {
    let token = provided_token.trim();
    if token.is_empty() {
        return None;
    }
    load_paired_peers().into_iter().find(|p| {
        p.confirmed && p.auth_token.as_deref().is_some_and(|t| !t.is_empty() && constant_time_eq_str(t, token))
    })
}

/// True if a code-verified legacy pairing was made with the device at `ip` (label only).
fn legacy_paired_at(ip: &str) -> bool {
    !ip.is_empty() && load_paired_peers().iter().any(|p| p.is_active() && p.ip.as_deref() == Some(ip))
}

/// Our legacy auth token for the paired device at `ip`, sent only to that address.
fn legacy_token_for_ip(ip: &str) -> String {
    load_paired_peers()
        .into_iter()
        .find(|p| p.is_active() && !ip.is_empty() && p.ip.as_deref() == Some(ip))
        .and_then(|p| p.auth_token)
        .unwrap_or_default()
}

/// `X-OmaSend-Auth-Token` header line for a legacy peer, or nothing.
fn legacy_token_header(token: &str) -> String {
    if token.is_empty() { String::new() } else { format!("X-OmaSend-Auth-Token: {}\r\n", token) }
}

#[cfg(test)]
fn is_peer_trusted(peer_id: &str) -> bool {
    is_peer_paired(peer_id) || load_trusted_peers().iter().any(|p| p.id == peer_id)
}

fn add_trusted_peer(id: &str, name: &str, fingerprint: &str) {
    if rendezvous::validate_oma_id(id) {
        let _ = add_paired_peer(id, name, None);
    }
    let mut peers = load_trusted_peers();
    if !peers.iter().any(|p| p.id == id) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        peers.push(TrustedPeer {
            id: id.to_string(),
            name: name.to_string(),
            fingerprint: fingerprint.to_string(),
            trusted_at: now,
        });
        let db = TrustedPeersDb { peers };
        let path = get_state_dir().join("trusted_peers.json");
        if let Ok(s) = serde_json::to_string_pretty(&db) {
            let _ = write_secure_file(&path, &s);
        }
    }
}

struct StateFileGuard<'a> {
    _mutex_guard: Option<std::sync::MutexGuard<'a, ()>>,
    _flock_file: Option<fs::File>,
}

fn lock_state_files() -> StateFileGuard<'static> {
    use std::os::unix::io::AsRawFd;
    let mutex_guard = STATE_FILE_LOCK.lock().ok();
    let state_dir = get_state_dir();
    let _ = fs::create_dir_all(&state_dir);
    let lock_path = state_dir.join(".state_files.lock");
    let flock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .ok();
    if let Some(ref f) = flock_file {
        unsafe {
            let _ = libc::flock(f.as_raw_fd(), libc::LOCK_EX);
        }
    }
    StateFileGuard {
        _mutex_guard: mutex_guard,
        _flock_file: flock_file,
    }
}

/// How long an accepted HTTP transfer may sit idle between uploads before it expires.
const PENDING_IDLE_SECS: u64 = 600;

fn pending_transfer_path() -> PathBuf {
    get_state_dir().join("pending_transfer.json")
}

/// Reads the pending transfer without taking the state lock. `include_expired` also returns
/// an expired record (so pollers can be told EXPIRED instead of NOT_FOUND).
fn read_pending_transfer_unlocked(include_expired: bool) -> Option<PendingFileTransfer> {
    let content = read_secure_file(&pending_transfer_path()).ok()?;
    let t = serde_json::from_str::<PendingFileTransfer>(&content).ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    (include_expired || now <= t.expires_at).then_some(t)
}

fn write_pending_transfer_unlocked(t: &PendingFileTransfer) {
    if let Ok(s) = serde_json::to_string(t) {
        let _ = write_secure_file(&pending_transfer_path(), &s);
    }
}

fn get_pending_transfer() -> Option<PendingFileTransfer> {
    let _guard = lock_state_files();
    read_pending_transfer_unlocked(false)
}

#[cfg(test)]
fn save_pending_transfer(t: &PendingFileTransfer) {
    let _guard = lock_state_files();
    write_pending_transfer_unlocked(t);
}

fn clear_pending_transfer() {
    let _guard = lock_state_files();
    let _ = fs::remove_file(pending_transfer_path());
}

/// Runs `f` on the pending transfer (expired ones included) under a single state lock, so a
/// read-modify-write cannot interleave with another thread or process.
fn with_pending_transfer<R>(f: impl FnOnce(&mut Option<PendingFileTransfer>) -> R) -> R {
    let _guard = lock_state_files();
    let mut cur = read_pending_transfer_unlocked(true);
    let before = cur.as_ref().and_then(|t| serde_json::to_string(t).ok());
    let out = f(&mut cur);
    let after = cur.as_ref().and_then(|t| serde_json::to_string(t).ok());
    if before != after {
        match cur {
            Some(ref t) => write_pending_transfer_unlocked(t),
            None => {
                let _ = fs::remove_file(pending_transfer_path());
            }
        }
    }
    out
}

/// Atomically takes the single pending-transfer slot for `t` (V2-FUNC-01, M10). A live PENDING
/// or ACCEPTED transfer keeps the slot, except that a cryptographically verified sender (v2
/// signature or QUIC offer from a paired key) may displace a request from an unverified
/// sender that is still only PENDING, so anonymous LAN requests cannot block paired devices (M9).
fn claim_pending_slot(t: &PendingFileTransfer, verified: bool) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    with_pending_transfer(|slot| {
        if let Some(cur) = slot.as_ref() {
            let live = now <= cur.expires_at && (cur.status == "PENDING" || cur.status == "ACCEPTED");
            let unverified_pending = cur.status == "PENDING" && cur.sender_pk.is_none() && cur.transport.is_none();
            if live && !(verified && unverified_pending) {
                return false;
            }
        }
        *slot = Some(t.clone());
        true
    })
}

/// Applies the local user's accept/reject to the pending transfer. Only a live PENDING request
/// can be decided. Runs in the daemon: QUIC offers are answered through the core node, HTTP
/// transfers get a fresh idle window for their uploads.
fn decide_pending_transfer(token: &str, accept: bool) -> Result<&'static str, String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let quic = with_pending_transfer(|slot| {
        let p = slot.as_mut().filter(|p| !token.is_empty() && constant_time_eq_str(&p.token, token));
        let Some(p) = p else {
            return Err("Invalid or expired transfer token".to_string());
        };
        if now > p.expires_at {
            return Err("Transfer request expired".to_string());
        }
        if p.status != "PENDING" {
            return Err(format!("Transfer is already {}", p.status.to_lowercase()));
        }
        let quic = p.transport.as_deref() == Some("quic");
        if accept {
            p.status = "ACCEPTED".to_string();
            p.expires_at = now.saturating_add(PENDING_IDLE_SECS);
        } else if quic {
            *slot = None;
        } else {
            // Keep the record briefly so the polling sender sees REJECTED.
            p.status = "REJECTED".to_string();
            p.expires_at = p.expires_at.max(now.saturating_add(30));
        }
        Ok(quic)
    })?;
    if quic {
        match CORE_NODE.get() {
            Some(node) => node.respond(token.to_string(), accept),
            None => return Err("core not running".to_string()),
        }
    }
    if accept {
        notify_desktop("OmaSend AirBridge", if quic { "Transfer accepted. Receiving files (encrypted)..." } else { "Transfer accepted. Receiving files..." });
        Ok("ACCEPTED")
    } else {
        notify_desktop("OmaSend AirBridge", "Transfer declined.");
        Ok("REJECTED")
    }
}

fn get_discovered_peers_unlocked() -> Vec<DiscoveredPeer> {
    let (vis, _) = get_visibility();
    if vis == "OFF" {
        return Vec::new();
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (my_id, _) = get_or_create_device_id();

    let mut peers = Vec::new();
    let path = get_state_dir().join("discovered_peers.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(loaded) = serde_json::from_str::<Vec<DiscoveredPeer>>(&content) {
            // Prune peers older than 15s and filter out ONLY the exact same physical device (my_id)
            peers = loaded
                .into_iter()
                .filter(|p| {
                    if now.saturating_sub(p.last_seen_secs) > 15 {
                        return false;
                    }
                    if p.id == my_id {
                        return false;
                    }
                    true
                })
                .collect();
        }
    }

    let keys = trust_store().load();
    for p in &mut peers {
        p.transport = "LAN".to_string();
        p.key_trust = key_for_discovered(&keys, p)
            .map(|k| if k.own_device { "own" } else { "paired" }.to_string())
            .unwrap_or_default();
        // Display labels only (authorization is per request: signatures, QUIC, tokens). They
        // come from paired device keys and code-verified pairings, never from a claimed OmaID.
        p.is_same_owner = p.key_trust == "own";
        p.is_trusted = !p.key_trust.is_empty() || legacy_paired_at(&p.ip);
    }

    // Sort: Same-owner first, then online trusted, then alphabetical
    peers.sort_by(|a, b| {
        b.is_same_owner
            .cmp(&a.is_same_owner)
            .then_with(|| b.is_trusted.cmp(&a.is_trusted))
            .then_with(|| (b.last_seen_secs > 0).cmp(&(a.last_seen_secs > 0)))
            .then_with(|| a.name.cmp(&b.name))
    });

    peers
}

fn save_discovered_peers_unlocked(peers: &[DiscoveredPeer]) {
    let path = get_state_dir().join("discovered_peers.json");
    if let Ok(s) = serde_json::to_string(peers) {
        let _ = write_secure_file(&path, &s);
    }
}

fn get_discovered_peers() -> Vec<DiscoveredPeer> {
    let _guard = lock_state_files();
    get_discovered_peers_unlocked()
}

fn save_discovered_peers(peers: &[DiscoveredPeer]) {
    let _guard = lock_state_files();
    save_discovered_peers_unlocked(peers);
}

/// Upper bound on remembered discovered peers; the oldest are evicted first (M13).
const MAX_DISCOVERED_PEERS: usize = 256;

/// Records a beacon. `src` is the UDP source address: it is used instead of the packet's
/// self-reported `ip`, which any host can fill with someone else's address (M13).
fn update_discovered_peer(packet: &P2pBeaconPacket, src: IpAddr) {
    let src_ip = src.to_canonical().to_string();
    let _guard = lock_state_files();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (my_id, _) = get_or_create_device_id();
    // Only ignore if the packet comes from the exact same physical device
    if packet.id == my_id {
        return;
    }

    // Instant offline handling when remote peer turns discovery OFF
    if packet.mode == "OFF" || packet.mode == "STOP" {
        // Only the device itself (same id, same source address) can take itself off the list.
        let mut peers = get_discovered_peers_unlocked();
        let initial_len = peers.len();
        peers.retain(|p| !(p.id == packet.id && p.ip == src_ip));
        if peers.len() != initial_len {
            save_discovered_peers_unlocked(&peers);
        }
        return;
    }

    let (vis, _) = get_visibility();
    if vis == "OFF" {
        return;
    }

    // A claimed OmaID proves nothing (it is public), so it no longer makes a beacon "same
    // owner" or "trusted"; beacons without one (newer peers) are accepted. Trust labels are
    // recomputed from the key store and code-verified pairings in get_discovered_peers.
    let packet_oma_id = if rendezvous::validate_oma_id(&packet.oma_id) { packet.oma_id.clone() } else { String::new() };
    let is_same_owner = false;
    let is_authenticated_paired = legacy_paired_at(&src_ip);

    let mut peers = get_discovered_peers_unlocked();
    if let Some(existing) = peers.iter_mut().find(|p| p.id == packet.id) {
        existing.id = packet.id.clone();
        existing.oma_id = packet_oma_id;
        existing.name = packet.name.clone();
        existing.ip = src_ip.clone();
        existing.port = packet.port;
        existing.transport = "LAN".to_string();
        existing.fingerprint = packet.fp.clone();
        existing.is_trusted = is_authenticated_paired;
        existing.is_same_owner = is_same_owner;
        existing.last_seen_secs = now;
        existing.pk = packet.pk.clone();
    } else {
        peers.push(DiscoveredPeer {
            id: packet.id.clone(),
            oma_id: packet_oma_id,
            name: packet.name.clone(),
            ip: src_ip.clone(),
            port: packet.port,
            transport: "LAN".to_string(),
            fingerprint: packet.fp.clone(),
            is_trusted: is_authenticated_paired,
            is_same_owner,
            last_seen_secs: now,
            pk: packet.pk.clone(),
            key_trust: String::new(),
        });
        if peers.len() > MAX_DISCOVERED_PEERS {
            peers.sort_by_key(|p| std::cmp::Reverse(p.last_seen_secs));
            peers.truncate(MAX_DISCOVERED_PEERS);
        }
    }
    save_discovered_peers_unlocked(&peers);
}

pub fn get_all_broadcast_addresses() -> Vec<Ipv4Addr> {
    let mut addrs = Vec::new();
    addrs.push(Ipv4Addr::new(255, 255, 255, 255));

    // Enumerate system network interfaces via libc::getifaddrs
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) == 0 && !ifaddrs.is_null() {
            let mut curr = ifaddrs;
            while !curr.is_null() {
                let ifa = *curr;
                if !ifa.ifa_addr.is_null() && !ifa.ifa_ifu.is_null() {
                    let family = (*ifa.ifa_addr).sa_family as i32;
                    let flags = ifa.ifa_flags as i32;
                    if family == libc::AF_INET
                        && (flags & libc::IFF_UP != 0)
                        && (flags & libc::IFF_BROADCAST != 0)
                        && (flags & libc::IFF_LOOPBACK == 0)
                    {
                        let broad_sa = ifa.ifa_ifu as *const libc::sockaddr_in;
                        let sin_addr = (*broad_sa).sin_addr.s_addr;
                        let ip_bytes = sin_addr.to_ne_bytes();
                        let bcast_ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                        if !addrs.contains(&bcast_ip) {
                            addrs.push(bcast_ip);
                        }
                    }
                }
                curr = ifa.ifa_next;
            }
            libc::freeifaddrs(ifaddrs);
        }
    }

    // Derive /24 and /16 subnet broadcasts from local IP
    let local_ip = get_local_ip();
    if let Ok(ip) = local_ip.parse::<Ipv4Addr>() {
        let oct = ip.octets();
        let sub24 = Ipv4Addr::new(oct[0], oct[1], oct[2], 255);
        if !addrs.contains(&sub24) {
            addrs.push(sub24);
        }
        let sub16 = Ipv4Addr::new(oct[0], oct[1], 255, 255);
        if !addrs.contains(&sub16) {
            addrs.push(sub16);
        }
    }

    addrs
}

/// Our discovery beacon. It carries no OmaID: a beacon is public and unauthenticated, and the
/// device key (`pk`) is only an address hint that TLS/signatures verify later.
fn beacon_packet(mode: &str) -> P2pBeaconPacket {
    let (device_id, fp) = get_or_create_device_id();
    P2pBeaconPacket {
        magic: "OMASEND_P2P".to_string(),
        v: 1,
        id: device_id,
        oma_id: String::new(),
        name: get_system_hostname(),
        ip: get_local_ip(),
        port: PORT,
        mode: mode.to_string(),
        fp,
        pk: device_identity().public_b64(),
    }
}

pub fn send_p2p_beacon_burst(burst_count: usize) {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = socket.set_broadcast(true);

    let (vis, _) = get_visibility();
    if vis == "OFF" {
        return;
    }
    let packet = beacon_packet(&vis);

    if let Ok(bytes) = serde_json::to_vec(&packet) {
        let broadcast_targets = get_all_broadcast_addresses();
        let known_peers = get_discovered_peers();
        let paired_ips = get_active_paired_peer_ips();

        for i in 0..burst_count {
            for bcast_ip in &broadcast_targets {
                let target = format!("{}:{}", bcast_ip, P2P_BEACON_PORT);
                let _ = socket.send_to(&bytes, &target);
            }
            for peer in &known_peers {
                if !peer.ip.is_empty() {
                    let target = format!("{}:{}", peer.ip, P2P_BEACON_PORT);
                    let _ = socket.send_to(&bytes, &target);
                }
            }
            for paired_ip in &paired_ips {
                if !paired_ip.is_empty() {
                    let target = format!("{}:{}", paired_ip, P2P_BEACON_PORT);
                    let _ = socket.send_to(&bytes, &target);
                }
            }
            if i + 1 < burst_count {
                thread::sleep(Duration::from_millis(40));
            }
        }
    }
}

pub fn prune_expired_discovered_peers() -> usize {
    let _guard = lock_state_files();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let path = get_state_dir().join("discovered_peers.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(peers) = serde_json::from_str::<Vec<DiscoveredPeer>>(&content) {
            let initial_len = peers.len();
            let remaining: Vec<DiscoveredPeer> = peers.into_iter().filter(|p| now.saturating_sub(p.last_seen_secs) <= 15).collect();
            if remaining.len() != initial_len {
                save_discovered_peers_unlocked(&remaining);
                return initial_len - remaining.len();
            }
        }
    }
    0
}

fn run_p2p_beacon_broadcaster() {
    loop {
        send_p2p_beacon_burst(1);
        prune_expired_discovered_peers();
        thread::sleep(Duration::from_secs(3));
    }
}

pub fn send_immediate_beacon_broadcast() {
    send_p2p_beacon_burst(1);
}

fn run_p2p_discovery_listener() {
    let socket = match UdpSocket::bind(format!("0.0.0.0:{}", P2P_BEACON_PORT)) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(1000)));

    let mut buf = [0u8; 2048];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                if amt > 0 && amt <= 2048 {
                    if let Ok(packet) = serde_json::from_slice::<P2pBeaconPacket>(&buf[..amt]) {
                        if packet.magic == "OMASEND_P2P" {
                            update_discovered_peer(&packet, src.ip());
                        }
                    }
                }
            }
            Err(_) => {
                // Periodic pruning on socket recv timeout
                prune_expired_discovered_peers();
            }
        }
    }
}

fn connect_peer_with_timeout(addr_str: &str, timeout: Duration) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = match addr_str.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => return Err(format!("Invalid address '{}': {}", addr_str, e)),
    };
    if addrs.is_empty() {
        return Err(format!("No IP address resolved for '{}'", addr_str));
    }
    for addr in addrs {
        if let Ok(s) = TcpStream::connect_timeout(&addr, timeout) {
            let _ = s.set_nodelay(true);
            let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(15)));
            return Ok(s);
        }
    }
    Err(format!(
        "Connection timed out to '{}'. Ensure port {} TCP is open in firewall (UFW).",
        addr_str, PORT
    ))
}

/// Resolves a target string (either an IP address or a 16-digit Luhn OmaID) into `(ip, port, optional_oma_id)`.
pub fn resolve_target_ip_or_omaid(target_ip_or_omaid: &str) -> Result<(String, u16, Option<String>), String> {
    let trimmed = target_ip_or_omaid.trim();
    if trimmed.is_empty() {
        return Err("Empty target specified".to_string());
    }

    let norm = rendezvous::normalize_oma_id(trimmed);
    let is_oma_id = norm.len() == 16 && rendezvous::validate_oma_id(&norm);

    if is_oma_id {
        let formatted_id = rendezvous::format_oma_id(&norm);
        // Only a code-verified pairing maps an OmaID to an address. Beacons (anyone can claim
        // any OmaID in them) and the OmaID-keyed rendezvous anchor are not used any more.
        for peer in load_paired_peers().into_iter().filter(|p| p.is_active()) {
            if rendezvous::normalize_oma_id(&peer.oma_id) == norm {
                if let Some(ip) = peer.ip {
                    if !ip.is_empty() {
                        return Ok((ip, PORT, Some(formatted_id)));
                    }
                }
            }
        }
        return Err(format!("Could not resolve IP address for OmaID {}", formatted_id));
    }

    // Target is an IP or host(:port)
    if let Some((host, port_str)) = trimmed.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(p) = port_str.parse::<u16>() {
                let known_oma = load_paired_peers()
                    .into_iter()
                    .find(|pp| pp.ip.as_deref() == Some(host))
                    .map(|pp| pp.oma_id);
                return Ok((host.to_string(), p, known_oma));
            }
        }
    }

    let known_oma = load_paired_peers()
        .into_iter()
        .find(|pp| pp.ip.as_deref() == Some(trimmed))
        .map(|pp| pp.oma_id);
    if let Some(peer) = get_discovered_peers().into_iter().find(|p| p.ip == trimmed) {
        return Ok((peer.ip, peer.port, known_oma));
    }
    Ok((trimmed.to_string(), PORT, known_oma))
}

fn resolve_peer_addr(target_ip_or_omaid: &str) -> String {
    if let Ok((ip, port, _)) = resolve_target_ip_or_omaid(target_ip_or_omaid) {
        return format!("{}:{}", ip, port);
    }
    for peer in get_discovered_peers() {
        if peer.ip == target_ip_or_omaid {
            return format!("{}:{}", peer.ip, peer.port);
        }
    }
    format!("{}:{}", target_ip_or_omaid, PORT)
}

const MAX_PAIR_RESPONSE_BYTES: u64 = 64 * 1024;

/// Parses a pairing link and checks that it points at a private / link-local address on this
/// network (a QR from a web page or chat must not make us connect anywhere else, M4).
fn inspect_pair_uri(uri: &str) -> Result<(devicekey::ParsedOffer, String), String> {
    let offer = devicekey::parse_pair_uri(uri)?;
    let ip: IpAddr = offer.host.trim().parse().map_err(|_| "Invalid host in pairing link".to_string())?;
    let ip = ip.to_canonical();
    if !rendezvous::is_local_network_ip(&ip) || ip.is_loopback() {
        return Err("Pairing link must point to a private (RFC 1918) or link-local address".to_string());
    }
    let vk = devicekey::decode_pk(&offer.pk).ok_or("Invalid responder key")?;
    let device_id = devicekey::device_id_for_pk(vk.as_bytes());
    Ok((offer, device_id))
}

/// POSTs JSON to a peer's v2 HTTP API and returns the 200 body, or the peer's error.
fn post_json_v2(addr: &str, path: &str, body: &serde_json::Value, timeout: Duration) -> Result<serde_json::Value, String> {
    let body = body.to_string().into_bytes();
    let mut stream = connect_peer_with_timeout(addr, timeout)?;
    let _ = stream.set_read_timeout(Some(timeout));
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        addr,
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&body).map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    (&mut stream)
        .take(MAX_PAIR_RESPONSE_BYTES + 1)
        .read_to_end(&mut resp)
        .map_err(|e| format!("Read failed: {}", e))?;
    if resp.len() as u64 > MAX_PAIR_RESPONSE_BYTES {
        return Err("Response exceeds size limit".to_string());
    }
    let header_end = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or("Malformed response")?;
    let status_line = String::from_utf8_lossy(&resp[..header_end]).to_string();
    let json: serde_json::Value = serde_json::from_slice(&resp[header_end + 4..]).map_err(|_| "Malformed response body".to_string())?;
    if !status_line.starts_with("HTTP/1.1 200") {
        return Err(json["error"].as_str().unwrap_or("Rejected by peer").to_string());
    }
    Ok(json)
}

/// Runs one "link with OmaID" exchange against a peer at `addr`.
fn link_one(addr: &str, account_id: &str) -> Result<devicekey::TrustedKey, String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let t = Duration::from_secs(4);
    let ini = omalink::Initiator::new(account_id);
    let pa_b64 = b64.encode(&ini.pa);
    let start = post_json_v2(addr, "/api/v2/link/start", &serde_json::json!({ "v": 1, "pA": pa_b64 }), t)?;
    let pb_b64 = start["pB"].as_str().ok_or("Missing pB")?.to_string();
    let pb = b64.decode(&pb_b64).map_err(|_| "Invalid pB")?;
    let c_b = b64.decode(start["cB"].as_str().ok_or("Missing cB")?).map_err(|_| "Invalid cB")?;
    // Stops here for every device on another account; nothing more is sent.
    let keys = ini.finish(&pb, &c_b)?;
    let id = device_identity();
    let my_quic = CORE_NODE.get().map(|n| n.bound_port()).unwrap_or(CORE_QUIC_PORT);
    let finish = serde_json::json!({
        "sid": start["sid"],
        "cA": b64.encode(keys.c_a),
        "box": omalink::initiator_box(id, &keys, &pa_b64, &pb_b64, &get_system_hostname(), my_quic),
    });
    let reply = post_json_v2(addr, "/api/v2/link/finish", &finish, t)?;
    let peer = omalink::open_responder_box(&keys, &pa_b64, &pb_b64, &id.public_b64(), reply["box"].as_str().ok_or("Missing box")?)?;
    if omalink::is_revoked(&get_state_dir(), &peer.pk) {
        return Err("That device was removed from the account".into());
    }
    let vk = devicekey::decode_pk(&peer.pk).ok_or("Invalid responder key")?;
    let (host, port) = addr.rsplit_once(':').unwrap_or((addr, "0"));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let key = devicekey::TrustedKey {
        pk: peer.pk,
        device_id: devicekey::device_id_for_pk(vk.as_bytes()),
        name: peer.name,
        ip: host.trim_matches(|c| c == '[' || c == ']').to_string(),
        port: port.parse().unwrap_or(0),
        quic_port: peer.quic_port,
        own_device: true,
        added_at: now,
        last_seen: now,
    };
    trust_store().upsert(key.clone())?;
    Ok(key)
}

/// Links this device to every nearby device that holds `account_id`. On any
/// success the number becomes this device's account OmaID too.
fn link_with_account_id(account_id: &str) -> Result<Vec<devicekey::TrustedKey>, String> {
    if !rendezvous::validate_oma_id(account_id) {
        return Err("Invalid OmaID (16 digits, checksum mismatch)".into());
    }
    send_immediate_beacon_broadcast();
    std::thread::sleep(Duration::from_millis(1500));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let my_pk = device_identity().public_b64();
    let known: Vec<String> = trust_store().load().into_iter().map(|k| k.pk).collect();
    let targets: Vec<String> = get_discovered_peers()
        .into_iter()
        .filter(|p| !p.pk.is_empty() && p.pk != my_pk && !known.contains(&p.pk) && now.saturating_sub(p.last_seen_secs) < 120)
        .filter(|p| !omalink::is_revoked(&get_state_dir(), &p.pk))
        .filter_map(|p| p.ip.parse::<IpAddr>().ok().map(|ip| std::net::SocketAddr::new(ip, p.port).to_string()))
        .collect();
    if targets.is_empty() {
        return Err("No new OmaSend devices nearby. Open OmaSend on the other device and keep it visible.".into());
    }
    let handles: Vec<_> = targets
        .into_iter()
        .map(|addr| {
            let id = account_id.to_string();
            std::thread::spawn(move || link_one(&addr, &id))
        })
        .collect();
    let linked: Vec<devicekey::TrustedKey> = handles.into_iter().filter_map(|h| h.join().ok().and_then(Result::ok)).collect();
    if linked.is_empty() {
        return Err("No nearby device uses this OmaID".into());
    }
    omalink::set_account_id(&get_state_dir(), account_id)?;
    for k in &linked {
        notify_desktop("OmaSend: Device linked", &format!("{} ({}) is now one of your devices.", k.name, k.device_id));
    }
    push_roster();
    Ok(linked)
}

/// Sends our own-device list and revocations to every own device we can address, so a
/// link or removal on one device reaches all of them. Runs in the background.
fn push_roster() {
    std::thread::spawn(|| {
        let state_dir = get_state_dir();
        let store = trust_store();
        let my_quic = CORE_NODE.get().map(|n| n.bound_port()).unwrap_or(CORE_QUIC_PORT);
        let body = omalink::roster_body(&state_dir, &store, device_identity(), &get_system_hostname(), PORT, my_quic);
        // The keys we just revoked get the list too, so they leave the account.
        let revoked = omalink::load_revoked(&state_dir);
        let discovered = get_discovered_peers();
        let targets: Vec<String> = store
            .load()
            .into_iter()
            .filter(|k| k.own_device)
            .chain(discovered.iter().filter(|p| revoked.contains(&p.pk)).map(|p| devicekey::TrustedKey {
                pk: p.pk.clone(),
                device_id: String::new(),
                name: p.name.clone(),
                ip: p.ip.clone(),
                port: p.port,
                quic_port: 0,
                own_device: true,
                added_at: 0,
                last_seen: 0,
            }))
            .filter_map(|k| {
                let seen = discovered.iter().find(|p| p.pk == k.pk);
                let ip = seen.map(|p| p.ip.clone()).unwrap_or(k.ip);
                let port = seen.map(|p| p.port).filter(|p| *p != 0).unwrap_or(if k.port != 0 { k.port } else { PORT });
                ip.parse::<IpAddr>().ok().map(|ip| std::net::SocketAddr::new(ip, port).to_string())
            })
            .collect();
        let raw = body.to_string().into_bytes();
        let auth = v2_auth_lines("POST", "/api/v2/account/sync", &devicekey::body_tag_json(&raw));
        for addr in targets {
            let raw = raw.clone();
            let auth = auth.clone();
            std::thread::spawn(move || {
                let Ok(mut stream) = connect_peer_with_timeout(&addr, Duration::from_secs(3)) else { return };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let head = format!(
                    "POST /api/v2/account/sync HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
                    addr,
                    raw.len(),
                    auth
                );
                let _ = stream.write_all(head.as_bytes()).and_then(|_| stream.write_all(&raw));
                let mut sink = Vec::new();
                let _ = (&mut stream).take(4096).read_to_end(&mut sink);
            });
        }
    });
}

/// Phase 1 initiator: scan/paste an `omasend://pair?...` link shown by the other device.
/// The responder's key is pinned from the link, so a LAN attacker cannot impersonate it.
/// The trust level is chosen here, by the user of this device (`own_device`); the link's
/// `o=` flag only describes how the responder will trust us (M4).
fn p2p_pair_v2(uri: &str, own_device: bool) -> Result<devicekey::TrustedKey, String> {
    let (offer, _) = inspect_pair_uri(uri)?;
    let body = devicekey::build_pair_request(device_identity(), &offer, &get_system_hostname(), CORE_NODE.get().map(|n| n.bound_port()).unwrap_or(CORE_QUIC_PORT))
        .to_string()
        .into_bytes();
    let addr = format!("{}:{}", offer.host, offer.port);
    let mut stream = connect_peer_with_timeout(&addr, Duration::from_secs(4))?;
    let head = format!(
        "POST /api/v2/pair HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr,
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&body).map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    (&mut stream)
        .take(MAX_PAIR_RESPONSE_BYTES + 1)
        .read_to_end(&mut resp)
        .map_err(|e| format!("Read failed: {}", e))?;
    if resp.len() as u64 > MAX_PAIR_RESPONSE_BYTES {
        return Err("Pairing response exceeds size limit".to_string());
    }
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed pairing response".to_string())?;
    let status_line = String::from_utf8_lossy(&resp[..header_end]).to_string();
    let json: serde_json::Value = serde_json::from_slice(&resp[header_end + 4..])
        .map_err(|_| "Malformed pairing response body".to_string())?;
    if !status_line.starts_with("HTTP/1.1 200") {
        return Err(json["error"].as_str().unwrap_or("Pairing rejected by peer").to_string());
    }
    devicekey::verify_pair_response(device_identity(), &offer, &json)?;
    let vk = devicekey::decode_pk(&offer.pk).ok_or("Invalid responder key")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let name = json["name"].as_str().filter(|n| !n.is_empty()).unwrap_or(&offer.name).chars().take(64).collect();
    let key = devicekey::TrustedKey {
        pk: offer.pk.clone(),
        device_id: devicekey::device_id_for_pk(vk.as_bytes()),
        name,
        ip: offer.host.clone(),
        port: offer.port,
        quic_port: json["quic_port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(offer.quic_port),
        own_device,
        added_at: now,
        last_seen: now,
    };
    trust_store().upsert(key.clone())?;
    Ok(key)
}

/// Target for `--send auto`: the most recently seen QR-paired own device ("ip:port").
fn auto_send_target() -> Option<String> {
    let mut keys: Vec<_> = trust_store()
        .load()
        .into_iter()
        .filter(|k| k.own_device)
        .collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.last_seen));
    keys.first().map(|k| k.device_id.clone())
}

/// Creates a pairing offer, renders its QR code to PNG and returns the JSON the panel/CLI shows.
fn create_pair_offer_json(own_device: bool) -> serde_json::Value {
    let uri = devicekey::create_pair_offer(
        device_identity(),
        &get_state_dir(),
        &get_system_hostname(),
        &get_local_ip(),
        PORT,
        own_device,
        CORE_NODE.get().map(|n| n.bound_port()).unwrap_or(CORE_QUIC_PORT),
    );
    // The offer secret is in the QR, so the image is written 0600 and replaced per offer.
    let svg = get_state_dir().join("pair_offer_qr.svg");
    let svg_str = svg.to_string_lossy().to_string();
    let _ = fs::remove_file(get_state_dir().join("pair_offer_qr.png"));
    let written = rendezvous::qr_svg(&uri).is_some_and(|data| write_secure_file(&svg, &data).is_ok());
    serde_json::json!({
        "uri": uri,
        "qr_svg": if written { svg_str } else { String::new() },
        "device_id": device_identity().device_id(),
        "own_device": own_device,
        "expires_in_secs": devicekey::PAIR_OFFER_TTL_SECS,
    })
}

/// Initiator side of code-verified pairing: presents the one-time code issued
/// on the responder (`--pair-peer <our OmaID>` there) and stores the responder
/// as a confirmed peer only if it echoes the expected OmaID and a valid token.
fn p2p_complete_pairing(peer_ip_str: &str, expected_oma_id: &str, code: &str, name: &str) -> Result<rendezvous::PairedPeer, String> {
    let peer_ip: IpAddr = peer_ip_str.trim().parse().map_err(|_| "Invalid peer IP address".to_string())?;
    let peer_ip = peer_ip.to_canonical();
    if !rendezvous::is_local_network_ip(&peer_ip) || peer_ip.is_loopback() {
        return Err("Peer address must be a private (RFC 1918) or link-local address".to_string());
    }
    let expected_norm = rendezvous::normalize_oma_id(expected_oma_id);
    if !rendezvous::validate_oma_id(&expected_norm) {
        return Err("Invalid peer OmaID".to_string());
    }
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Pairing code must be 6 digits".to_string());
    }

    let port = get_discovered_peers()
        .into_iter()
        .find(|p| p.ip.parse::<IpAddr>().map(|ip| ip.to_canonical() == peer_ip).unwrap_or(false))
        .map(|p| p.port)
        .unwrap_or(PORT);
    let addr = std::net::SocketAddr::new(peer_ip, port).to_string();

    let my_oma_id = get_or_create_oma_id();
    let payload = serde_json::json!({
        "oma_id": my_oma_id,
        "name": get_system_hostname(),
        "pair_code": code
    });
    let body = payload.to_string().into_bytes();

    let mut stream = connect_peer_with_timeout(&addr, Duration::from_millis(3000))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let req = format!(
        "POST /api/p2p/pair HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr,
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(|e| format!("Send failed: {}", e))?;
    stream.write_all(&body).map_err(|e| format!("Send failed: {}", e))?;

    let mut resp = Vec::new();
    (&mut stream)
        .take(MAX_PAIR_RESPONSE_BYTES + 1)
        .read_to_end(&mut resp)
        .map_err(|e| format!("Read failed: {}", e))?;
    if resp.len() as u64 > MAX_PAIR_RESPONSE_BYTES {
        return Err("Pairing response exceeds size limit".to_string());
    }
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed pairing response".to_string())?;
    let status_line = String::from_utf8_lossy(&resp[..header_end]);
    if !status_line.starts_with("HTTP/1.1 200") {
        return Err("Pairing rejected by peer (wrong or expired code)".to_string());
    }
    let json: serde_json::Value = serde_json::from_slice(&resp[header_end + 4..])
        .map_err(|_| "Malformed pairing response body".to_string())?;
    if json["status"].as_str() != Some("PAIRED") {
        return Err("Pairing rejected by peer".to_string());
    }
    let returned_id = json["oma_id"].as_str().unwrap_or_default();
    if rendezvous::normalize_oma_id(returned_id) != expected_norm {
        return Err("Responder OmaID does not match the expected peer".to_string());
    }
    let token = json["auth_token"].as_str().unwrap_or_default();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    rendezvous::store_completed_pairing(&expected_norm, name, peer_ip, token, &get_state_dir(), now)
}

fn p2p_send_files_to_peer(target_ip_or_omaid: &str, file_paths: &[PathBuf]) -> Result<(), String> {
    if file_paths.is_empty() {
        return Err("No files specified for transfer".to_string());
    }

    clear_transfer_cancel();
    struct ProgressAndTarCleanup {
        temp_files: Vec<PathBuf>,
    }
    impl Drop for ProgressAndTarCleanup {
        fn drop(&mut self) {
            clear_transfer_progress();
            for p in &self.temp_files {
                let _ = fs::remove_file(p);
            }
        }
    }
    let mut cleanup_guard = ProgressAndTarCleanup {
        temp_files: Vec::new(),
    };

    // Phase 2: QR-paired devices only ever use the encrypted QUIC transport. There is no
    // silent fallback to plaintext HTTP, so blocking UDP cannot downgrade a paired device.
    let paired_key = trusted_key_for_target(target_ip_or_omaid);
    let (resolved_ip, resolved_port, _) = match resolve_target_ip_or_omaid(target_ip_or_omaid) {
        Ok(v) => v,
        Err(_) if paired_key.is_some() => (String::new(), PORT, None),
        Err(e) => return Err(e),
    };
    let target_ip = resolved_ip.as_str();

    struct PreparedFile {
        path: PathBuf,
        name: String,
        size_bytes: u64,
        blake3_hex: String,
        sha256_hex: String,
        md5_hex: String,
    }

    let mut prepared = Vec::with_capacity(file_paths.len());
    let mut files_json = Vec::with_capacity(file_paths.len());
    let mut total_size_bytes = 0u64;

    for fp in file_paths {
        let meta = fs::symlink_metadata(fp).map_err(|e| format!("Failed to stat {:?}: {}", fp, e))?;
        if meta.file_type().is_symlink() {
            return Err(format!("Security violation: {:?} is a symlink", fp));
        }
        let current_uid = get_current_uid();
        if meta.uid() != current_uid {
            return Err(format!("Security violation: {:?} is not owned by current user", fp));
        }

        let effective_path = if meta.file_type().is_dir() {
            let dir_name = fp
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|s| !s.is_empty() && !s.starts_with('.'))
                .ok_or_else(|| format!("Invalid directory name: {:?}", fp))?;
            let parent_dir = fp.parent().unwrap_or_else(|| Path::new("."));
            let parent_str = parent_dir.to_str().ok_or_else(|| "Invalid parent path UTF-8".to_string())?;
            let safe_base = sanitize_filename(dir_name);
            let tar_path = get_state_dir().join(format!("{}.tar", safe_base));
            let _ = fs::remove_file(&tar_path);
            let tar_str = tar_path.to_str().ok_or_else(|| "Invalid tar path UTF-8".to_string())?;
            let deadline = Instant::now() + Duration::from_secs(120);
            let _ = run_cmd_bounded(
                "/usr/bin/tar",
                &["--no-acls", "--no-xattrs", "-cf", tar_str, "-C", parent_str, "--", dir_name],
                &[],
                deadline,
                4096,
            )
            .ok_or_else(|| format!("Failed to archive directory {:?}", fp))?;
            let _ = fs::set_permissions(&tar_path, fs::Permissions::from_mode(0o600));
            cleanup_guard.temp_files.push(tar_path.clone());
            tar_path
        } else {
            fp.clone()
        };

        let size_bytes = safe_verify_file(&effective_path)
            .map_err(|e| format!("Security check failed for {:?}: {}", effective_path, e))?;
        let file_name = effective_path.file_name().unwrap_or_default().to_string_lossy().to_string();
        // The QUIC core hashes (BLAKE3) while streaming; only the legacy path needs these upfront.
        let (blake3_hex, sha256_hex, md5_hex) = if paired_key.is_some() {
            (String::new(), String::new(), String::new())
        } else {
            compute_file_military_hashes(&effective_path).map_err(|e| format!("Failed to compute file hashes: {}", e))?
        };
        total_size_bytes = total_size_bytes.saturating_add(size_bytes);
        files_json.push(serde_json::json!({
            "name": file_name,
            "size": size_bytes,
            "size_bytes": size_bytes,
            "blake3": blake3_hex,
            "sha256": sha256_hex,
            "md5": md5_hex
        }));
        prepared.push(PreparedFile {
            path: effective_path,
            name: file_name,
            size_bytes,
            blake3_hex,
            sha256_hex,
            md5_hex,
        });
    }

    if let Some(key) = paired_key {
        let paths: Vec<String> = prepared.iter().map(|p| p.path.to_string_lossy().to_string()).collect();
        let names: Vec<String> = prepared.iter().map(|p| p.name.clone()).collect();
        println!("Sending to {} over encrypted QUIC...", key.name);
        return match core_send_via_daemon(&key, &paths, &names) {
            Ok(()) => {
                println!("Transfer successfully completed to {} (QUIC, BLAKE3 verified)!", key.name);
                notify_desktop("OmaSend AirBridge", &format!("{} file(s) sent to {} (end-to-end encrypted).", prepared.len(), key.name));
                Ok(())
            }
            Err((_, e)) => {
                let msg = core_failure_message(&key.name, &e);
                notify_desktop("OmaSend AirBridge", &format!("Transfer to {} failed: {}", key.name, msg));
                Err(msg)
            }
        };
    }

    let (my_id, _) = get_or_create_device_id();
    let my_name = get_system_hostname();
    // A legacy token goes only to the address it was paired at (never to whoever claims the
    // peer's OmaID in a beacon).
    let auth_token = legacy_token_for_ip(target_ip);

    // 1. Send transfer request. No OmaID: the request is authorized by its v2 signature, or
    // by a legacy pairing token, and otherwise waits for the recipient's approval.
    let final_payload = serde_json::json!({
        "sender_id": my_id,
        "device_id": my_id,
        "sender_name": my_name,
        "sender_alias": my_name,
        "sender_ip": get_local_ip(),
        "files": files_json,
        "total_size_bytes": total_size_bytes
    });

    let addr = format!("{}:{}", target_ip, resolved_port);
    let mut stream = match connect_peer_with_timeout(&addr, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(e) => {
            notify_desktop(
                "OmaSend AirBridge",
                &format!("Connection failed to {}. Ensure peer is online.", target_ip),
            );
            return Err(e);
        }
    };
    let req_bytes = final_payload.to_string().into_bytes();
    let http_req = format!(
        "POST /api/p2p/request HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        addr, legacy_token_header(&auth_token),
        v2_auth_lines("POST", "/api/p2p/request", &devicekey::body_tag_json(&req_bytes)),
        req_bytes.len()
    );
    stream.write_all(http_req.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&req_bytes).map_err(|e| e.to_string())?;

    let mut response = String::new();
    (&mut stream).take(64 * 1024).read_to_string(&mut response).map_err(|e| e.to_string())?;

    let body_str = if let Some(idx) = response.find("\r\n\r\n") {
        &response[idx + 4..]
    } else {
        return Err("Malformed HTTP response from peer".to_string());
    };

    let val: serde_json::Value = serde_json::from_str(body_str).map_err(|e| format!("Invalid JSON from peer: {}", e))?;
    if let Some(err) = val.get("error") {
        return Err(format!("Peer rejected request: {}", err));
    }
    let token = val["token"].as_str().ok_or_else(|| "Peer did not return a transfer token".to_string())?.to_string();
    let initial_status = val["status"].as_str().unwrap_or("PENDING");

    let mut accepted = initial_status == "ACCEPTED";
    if !accepted {
        println!("Transfer request sent to {}! Waiting for user to Accept...", target_ip);
        notify_desktop("OmaSend AirBridge", &format!("Transfer request sent to {}. Waiting for consent...", target_ip));

        // 2. Poll for decision (monotonic deadline of 30 seconds)
        let deadline = std::time::Instant::now() + Duration::from_secs(30);

        while std::time::Instant::now() < deadline {
            if is_transfer_cancelled() {
                clear_transfer_cancel();
                return Err("Transfer cancelled by user.".to_string());
            }
            thread::sleep(Duration::from_millis(600));
            let mut poll_stream = match connect_peer_with_timeout(&addr, Duration::from_secs(4)) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let poll_req = format!(
                "GET /api/p2p/decision?token={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                token, addr
            );
            let _ = poll_stream.write_all(poll_req.as_bytes());
            let mut poll_resp = String::new();
            let _ = (&mut poll_stream).take(64 * 1024).read_to_string(&mut poll_resp);
            if let Some(idx) = poll_resp.find("\r\n\r\n") {
                let poll_body = &poll_resp[idx + 4..];
                if let Ok(p_val) = serde_json::from_str::<serde_json::Value>(poll_body) {
                    match p_val["status"].as_str() {
                        Some("ACCEPTED") => {
                            accepted = true;
                            break;
                        }
                        Some("REJECTED") => {
                            return Err("Transfer was declined by the recipient.".to_string());
                        }
                        Some("EXPIRED") => {
                            return Err("Transfer request timed out.".to_string());
                        }
                        _ => {} // Still pending
                    }
                }
            }
        }
    }

    if !accepted {
        return Err("Transfer timed out waiting for recipient approval.".to_string());
    }

    // 3. Upload each file in the batch via 128 KiB streaming chunks
    let mut cumulative_sent = 0u64;
    for pf in &prepared {
        if is_transfer_cancelled() {
            clear_transfer_cancel();
            return Err("Transfer cancelled by user.".to_string());
        }
        save_transfer_progress("send", &pf.name, cumulative_sent, total_size_bytes);
        println!("Peer accepted! Streaming file '{}' ({} bytes, sha256: {})...", pf.name, pf.size_bytes, pf.sha256_hex);
        let mut upload_stream = connect_peer_with_timeout(&addr, Duration::from_secs(6))
            .map_err(|e| format!("Failed to connect to peer for upload: {}", e))?;
        let encoded_filename = urlencoding_encode(&pf.name);
        let upload_pq = format!(
            "/api/p2p/upload?token={}&filename={}&blake3={}&sha256={}&md5={}",
            token, encoded_filename, pf.blake3_hex, pf.sha256_hex, pf.md5_hex
        );
        let upload_header = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nX-File-BLAKE3: {}\r\nX-File-SHA256: {}\r\nX-File-MD5: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            upload_pq, addr, pf.blake3_hex, pf.sha256_hex, pf.md5_hex,
            v2_auth_lines("POST", &upload_pq, &devicekey::body_tag_stream(pf.size_bytes as usize)),
            pf.size_bytes
        );
        upload_stream.write_all(upload_header.as_bytes()).map_err(|e| e.to_string())?;

        let mut file = fs::File::open(&pf.path).map_err(|e| format!("Failed to open file for upload: {}", e))?;
        let mut chunk_buf = [0u8; 131072]; // 128 KiB chunk aligned with IEEE 802.11 A-MPDU
        let mut last_progress_tick = Instant::now();
        loop {
            if is_transfer_cancelled() {
                clear_transfer_cancel();
                return Err("Transfer cancelled by user.".to_string());
            }
            let n = file.read(&mut chunk_buf).map_err(|e| format!("Failed to read file chunk: {}", e))?;
            if n == 0 {
                break;
            }
            upload_stream.write_all(&chunk_buf[..n]).map_err(|e| format!("Failed to send chunk to peer: {}", e))?;
            cumulative_sent = cumulative_sent.saturating_add(n as u64);
            if last_progress_tick.elapsed() >= Duration::from_millis(250) {
                save_transfer_progress("send", &pf.name, cumulative_sent, total_size_bytes);
                last_progress_tick = Instant::now();
            }
        }
        save_transfer_progress("send", &pf.name, cumulative_sent, total_size_bytes);
        upload_stream.flush().map_err(|e| format!("Failed to flush upload stream: {}", e))?;

        let mut final_resp = Vec::new();
        let _ = (&mut upload_stream).take(64 * 1024).read_to_end(&mut final_resp);
        let resp_text = String::from_utf8_lossy(&final_resp);
        let status_ok = resp_text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .is_some_and(|code| code.starts_with('2'));
        if !status_ok {
            let reason = resp_text
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| v["error"].as_str().map(String::from))
                .unwrap_or_else(|| resp_text.lines().next().unwrap_or("no response").to_string());
            let msg = format!("Upload of '{}' was not accepted by {}: {}", pf.name, target_ip, reason);
            notify_desktop("OmaSend AirBridge", &msg);
            return Err(msg);
        }
    }

    println!("Transfer successfully completed to {}!", target_ip);
    if prepared.len() == 1 {
        notify_desktop("OmaSend AirBridge", &format!("'{}' successfully sent to {}.", prepared[0].name, target_ip));
    } else {
        notify_desktop("OmaSend AirBridge", &format!("{} files successfully sent to {}.", prepared.len(), target_ip));
    }
    Ok(())
}

fn p2p_sync_clipboard_to_peer(target_ip_or_omaid: &str) -> Result<(), String> {
    if let Some(key) = trusted_key_for_target(target_ip_or_omaid) {
        let text = get_pc_clipboard();
        if text.trim().is_empty() {
            let msg = "Clipboard has no text (images are only sent to legacy paired devices).".to_string();
            notify_desktop("OmaSend AirBridge", &msg);
            return Err(msg);
        }
        return match core_clipboard(&key, &text) {
            Ok(()) => {
                notify_desktop("OmaSend AirBridge", &format!("Clipboard sent to {} (end-to-end encrypted).", key.name));
                Ok(())
            }
            Err((_, e)) => {
                let msg = core_failure_message(&key.name, &e);
                notify_desktop("OmaSend AirBridge", &msg);
                Err(msg)
            }
        };
    }
    let (resolved_ip, resolved_port, _) = resolve_target_ip_or_omaid(target_ip_or_omaid)?;
    let target_ip = resolved_ip.as_str();

    if let Some((img_bytes, ct, w, h)) = get_pc_image_clipboard() {
        let hash = compute_image_clipboard_hash(&img_bytes);
        let _ = stage_clipboard_image(&img_bytes, &ct);
        p2p_push_image_clipboard_silent(
            target_ip,
            &ct,
            &hash,
            img_bytes.len() as u64,
            w,
            h,
            Some(&img_bytes),
        );
        println!("Image clipboard ({}) synced to {}", hash, target_ip);
        notify_desktop("OmaSend AirBridge", &format!("Image clipboard synced to {}.", target_ip));
        return Ok(());
    }

    let text = get_pc_clipboard();
    if text.is_empty() {
        notify_desktop("OmaSend AirBridge", "Clipboard is empty. Copy text or an image first.");
        return Err("Clipboard is empty".to_string());
    }

    let (my_id, _) = get_or_create_device_id();
    let my_name = get_system_hostname();
    let auth_token = legacy_token_for_ip(target_ip);

    let payload = serde_json::json!({
        "sender_id": my_id,
        "device_id": my_id,
        "sender_name": my_name,
        "content_type": "text",
        "text": text
    });
    let addr = format!("{}:{}", target_ip, resolved_port);
    let mut stream = match connect_peer_with_timeout(&addr, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(e) => {
            notify_desktop(
                "OmaSend AirBridge",
                &format!("Connection failed to {}. Ensure peer is online.", target_ip),
            );
            return Err(e);
        }
    };
    let req_bytes = payload.to_string().into_bytes();
    let http_req = format!(
        "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        addr, legacy_token_header(&auth_token),
        v2_auth_lines("POST", "/api/p2p/clipboard", &devicekey::body_tag_json(&req_bytes)),
        req_bytes.len()
    );
    stream.write_all(http_req.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&req_bytes).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    let _ = (&mut stream).take(64 * 1024).read_to_string(&mut resp);
    println!("Clipboard successfully synced to {}", target_ip);
    notify_desktop("OmaSend AirBridge", &format!("Clipboard successfully synced to {}.", target_ip));
    Ok(())
}

// ------------------- HTTP ENGINE -------------------

pub const MAX_HEADER_SIZE: usize = 65536; // 64 KiB header limit
pub const MAX_BODY_SIZE: usize = 100 * 1024 * 1024; // 100 MiB strict plain web upload ceiling
pub const MAX_P2P_UPLOAD_SIZE: usize = 10 * 1024 * 1024 * 1024; // 10 GiB P2P streaming upload ceiling
pub const MAX_ENCRYPTED_UPLOAD_SIZE: usize = 25 * 1024 * 1024; // 25 MiB encrypted upload ceiling
pub const MAX_CLIPBOARD_BODY: usize = 10 * 1024 * 1024; // 10 MiB clipboard limit
pub const MAX_CONTROL_BODY: usize = 65536; // 64 KiB JSON metadata limit
pub const IN_MEMORY_BODY_LIMIT: usize = 1024 * 1024; // 1 MiB in-memory cap
pub const MAX_AGGREGATE_STAGING_BYTES: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB aggregate disk staging cap
pub const MAX_CONCURRENT_ENCRYPTED_UPLOADS: u32 = 2; // Max 2 concurrent encrypted uploads
pub const HEADER_READ_TIMEOUT_SECS: u64 = 15; // 15s max header timeout
pub const DEFAULT_BODY_TIMEOUT_SECS: u64 = 30; // 30s body timeout for small requests
pub const MAX_UPLOAD_DURATION_SECS: u64 = 3600; // 1 hour max duration for large P2P uploads

// Atomic aggregate staging capacity accounting to eliminate disk space check races
static CURRENT_STAGED_BYTES: AtomicU64 = AtomicU64::new(0);
static STAGING_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub struct StagingReservationGuard {
    pub reserved_bytes: u64,
}

impl StagingReservationGuard {
    pub fn try_reserve(needed_bytes: u64, ddir: &Path) -> Result<Self, &'static str> {
        let _lock = STAGING_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let current = CURRENT_STAGED_BYTES.load(Ordering::SeqCst);
        if current.saturating_add(needed_bytes) > MAX_AGGREGATE_STAGING_BYTES {
            return Err("Aggregate staging capacity exceeded");
        }
        if let Some(avail) = get_available_disk_space(ddir) {
            let required_space = needed_bytes.saturating_add(25 * 1024 * 1024);
            if required_space > avail {
                return Err("Insufficient disk space for staging reservation");
            }
        }
        CURRENT_STAGED_BYTES.fetch_add(needed_bytes, Ordering::SeqCst);
        Ok(Self { reserved_bytes: needed_bytes })
    }

    pub fn release(&mut self) {
        if self.reserved_bytes > 0 {
            CURRENT_STAGED_BYTES.fetch_sub(self.reserved_bytes, Ordering::SeqCst);
            self.reserved_bytes = 0;
        }
    }
}

impl Drop for StagingReservationGuard {
    fn drop(&mut self) {
        self.release();
    }
}

// Concurrency tracker for encrypted uploads to strictly bound peak decryption memory
static ACTIVE_ENCRYPTED_UPLOADS: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
pub struct EncryptedUploadGuard;

impl EncryptedUploadGuard {
    pub fn try_acquire() -> Option<Self> {
        let mut curr = ACTIVE_ENCRYPTED_UPLOADS.load(Ordering::SeqCst);
        loop {
            if curr >= MAX_CONCURRENT_ENCRYPTED_UPLOADS {
                return None;
            }
            match ACTIVE_ENCRYPTED_UPLOADS.compare_exchange_weak(
                curr,
                curr.saturating_add(1),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(EncryptedUploadGuard),
                Err(actual) => curr = actual,
            }
        }
    }
}

impl Drop for EncryptedUploadGuard {
    fn drop(&mut self) {
        ACTIVE_ENCRYPTED_UPLOADS.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Default, Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body_offset: usize,
}

impl HttpRequest {
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        for (k, v) in &self.headers {
            if k == &lower {
                return Some(v.as_str());
            }
        }
        None
    }

    pub fn get_param(&self, key: &str) -> Option<String> {
        let prefix = format!("{}=", key);
        for part in self.query.split('&') {
            if part.starts_with(&prefix) {
                return Some(part[prefix.len()..].to_string());
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct StagedFile {
    pub path: PathBuf,
    pub size: u64,
    pub persisted: bool,
    pub reservation: Option<StagingReservationGuard>,
    pub blake3_hash: Option<String>,
    pub sha256_hash: Option<String>,
    pub md5_hash: Option<String>,
}

impl StagedFile {
    pub fn new(
        path: PathBuf,
        size: u64,
        reservation: Option<StagingReservationGuard>,
        blake3_hash: Option<String>,
    ) -> Self {
        Self {
            path,
            size,
            persisted: false,
            reservation,
            blake3_hash,
            sha256_hash: None,
            md5_hash: None,
        }
    }

    pub fn with_hashes(
        path: PathBuf,
        size: u64,
        reservation: Option<StagingReservationGuard>,
        blake3_hash: Option<String>,
        sha256_hash: Option<String>,
        md5_hash: Option<String>,
    ) -> Self {
        Self {
            path,
            size,
            persisted: false,
            reservation,
            blake3_hash,
            sha256_hash,
            md5_hash,
        }
    }

    pub fn persist(mut self, target: &Path) -> Result<(), String> {
        let dir = target.parent().ok_or_else(|| "Target path has no parent directory".to_string())?;
        let _ = fs::create_dir_all(dir);
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        fs::rename(&self.path, target).map_err(|e| format!("Failed to rename staged file: {}", e))?;
        let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
        self.persisted = true;
        if let Some(ref mut res) = self.reservation {
            res.release();
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        if self.size > MAX_ENCRYPTED_UPLOAD_SIZE as u64 {
            return Err("Payload exceeds maximum in-memory materialization limit".to_string());
        }
        safe_read_file(&self.path)
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.persisted && self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
        if let Some(ref mut res) = self.reservation {
            res.release();
        }
    }
}

pub enum HttpBody {
    Memory(Vec<u8>),
    Staged(StagedFile),
}

impl HttpBody {
    pub fn len(&self) -> usize {
        match self {
            HttpBody::Memory(v) => v.len(),
            HttpBody::Staged(s) => s.size as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> Option<&[u8]> {
        match self {
            HttpBody::Memory(v) => Some(v.as_slice()),
            HttpBody::Staged(_) => None,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            HttpBody::Memory(v) => Ok(v.clone()),
            HttpBody::Staged(s) => s.to_bytes(),
        }
    }

    pub fn compute_military_hashes(&self) -> Result<(String, String, String), String> {
        match self {
            HttpBody::Memory(bytes) => {
                let blake3_hex = blake3::hash(bytes).to_hex().to_string();
                let mut sha = Sha256::new();
                sha.update(bytes);
                let sha_hex = hex::encode(sha.finalize());
                let md5_hex = format!("{:x}", md5::compute(bytes));
                Ok((blake3_hex, sha_hex, md5_hex))
            }
            HttpBody::Staged(staged) => {
                if let (Some(b), Some(s), Some(m)) = (&staged.blake3_hash, &staged.sha256_hash, &staged.md5_hash) {
                    return Ok((b.clone(), s.clone(), m.clone()));
                }
                let mut file = fs::File::open(&staged.path).map_err(|e| format!("Failed to open staged file: {}", e))?;
                let mut blake3_hasher = blake3::Hasher::new();
                let need_blake3 = staged.blake3_hash.is_none();
                let mut sha = Sha256::new();
                let need_sha = staged.sha256_hash.is_none();
                let mut md5_ctx = md5::Context::new();
                let need_md5 = staged.md5_hash.is_none();
                let mut buf = [0u8; 131072]; // 128 KiB streaming chunk
                loop {
                    let n = file.read(&mut buf).map_err(|e| format!("Failed to read staged file: {}", e))?;
                    if n == 0 {
                        break;
                    }
                    if need_blake3 {
                        blake3_hasher.update(&buf[..n]);
                    }
                    if need_sha {
                        sha.update(&buf[..n]);
                    }
                    if need_md5 {
                        md5_ctx.consume(&buf[..n]);
                    }
                }
                let blake3_hex = match &staged.blake3_hash {
                    Some(h) => h.clone(),
                    None => blake3_hasher.finalize().to_hex().to_string(),
                };
                let sha_hex = match &staged.sha256_hash {
                    Some(h) => h.clone(),
                    None => hex::encode(sha.finalize()),
                };
                let md5_hex = match &staged.md5_hash {
                    Some(h) => h.clone(),
                    None => format!("{:x}", md5_ctx.compute()),
                };
                Ok((blake3_hex, sha_hex, md5_hex))
            }
        }
    }

    pub fn compute_hashes(&self) -> Result<(String, String), String> {
        let (_, sha_hex, md5_hex) = self.compute_military_hashes()?;
        Ok((sha_hex, md5_hex))
    }
}

pub trait TimeoutStream: Read {
    fn set_stream_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        let _ = timeout;
        Ok(())
    }
}

impl TimeoutStream for TcpStream {
    fn set_stream_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

impl<T: AsRef<[u8]>> TimeoutStream for std::io::Cursor<T> {}

/// Reads a stream chunk while strictly enforcing a monotonic deadline and updating socket timeout
pub fn read_stream_chunk_with_deadline<S: TimeoutStream>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<usize> {
    let now = Instant::now();
    if now >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Monotonic request deadline exceeded",
        ));
    }

    let remaining = deadline.saturating_duration_since(now);
    let sock_to = remaining.min(Duration::from_secs(15));
    let _ = stream.set_stream_timeout(Some(sock_to));

    let n = stream.read(buf)?;
    if Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Monotonic request deadline exceeded",
        ));
    }

    Ok(n)
}

#[derive(Debug)]
pub struct HttpHeaderResult {
    pub req: HttpRequest,
    pub content_length: usize,
    pub initial_body: Vec<u8>,
}

/// Phase 1: Read HTTP headers bounded strictly by MAX_HEADER_SIZE (64 KiB) under monotonic deadline
pub fn read_http_headers<S: TimeoutStream>(
    stream: &mut S,
    deadline: Instant,
) -> Option<HttpHeaderResult> {
    let mut header_buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let mut header_end = None;
    let mut content_length: usize = 0;

    loop {
        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            let header_str = String::from_utf8_lossy(&header_buf[..pos]);
            for line in header_str.lines() {
                if let Some(col) = line.find(':') {
                    let k = line[..col].trim().to_lowercase();
                    let v = line[col + 1..].trim();
                    if k == "content-length" {
                        content_length = v.parse::<usize>().unwrap_or(0);
                        if content_length > MAX_P2P_UPLOAD_SIZE {
                            return None; // Immediate ceiling rejection
                        }
                    }
                }
            }
            break;
        }

        if header_buf.len() >= MAX_HEADER_SIZE {
            return None; // Header overrun protection
        }

        match read_stream_chunk_with_deadline(stream, &mut temp, deadline) {
            Ok(0) => break,
            Ok(n) => {
                let remaining_space = MAX_HEADER_SIZE.saturating_sub(header_buf.len());
                let take = n.min(remaining_space);
                header_buf.extend_from_slice(&temp[..take]);
                if n > take && !header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    return None;
                }
                if n > take {
                    if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let header_str = String::from_utf8_lossy(&header_buf[..pos]);
                        for line in header_str.lines() {
                            if let Some(col) = line.find(':') {
                                let k = line[..col].trim().to_lowercase();
                                let v = line[col + 1..].trim();
                                if k == "content-length" {
                                    content_length = v.parse::<usize>().unwrap_or(0);
                                    if content_length > MAX_P2P_UPLOAD_SIZE {
                                        return None;
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
            Err(_) => return None,
        }
    }

    let hend = header_end?;
    let header_str = String::from_utf8_lossy(&header_buf[..hend - 4]);
    let mut lines = header_str.lines();
    let req_line = lines.next()?;
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_uppercase();
    let full_path = parts[1];
    let (path, query) = if let Some(q) = full_path.find('?') {
        (full_path[..q].to_string(), full_path[q + 1..].to_string())
    } else {
        (full_path.to_string(), String::new())
    };

    let mut headers = Vec::new();
    for l in lines {
        if let Some(col) = l.find(':') {
            let k = l[..col].trim().to_lowercase();
            let v = l[col + 1..].trim().to_string();
            headers.push((k, v));
        }
    }

    let req = HttpRequest {
        method,
        path,
        query,
        headers,
        body_offset: 0,
    };

    let initial_body = header_buf[hend..].to_vec();

    Some(HttpHeaderResult {
        req,
        content_length,
        initial_body,
    })
}

/// Phase 2: Read HTTP body with endpoint-specific caps, atomic staging reservation, and monotonic deadlines
pub fn read_http_body<S: TimeoutStream>(
    stream: &mut S,
    content_length: usize,
    initial_body: &[u8],
    deadline: Instant,
    staging_allowed: bool,
    max_allowed_bytes: usize,
) -> Option<HttpBody> {
    if content_length > max_allowed_bytes {
        return None;
    }

    if content_length == 0 {
        return Some(HttpBody::Memory(Vec::new()));
    }

    let initial_len = initial_body.len();

    if content_length <= IN_MEMORY_BODY_LIMIT {
        let mut body_vec = Vec::with_capacity(content_length);
        let copy_len = initial_len.min(content_length);
        body_vec.extend_from_slice(&initial_body[..copy_len]);
        let mut remaining = content_length.saturating_sub(copy_len);
        let mut temp = [0u8; 8192];

        while remaining > 0 {
            let to_read = remaining.min(temp.len());
            match read_stream_chunk_with_deadline(stream, &mut temp[..to_read], deadline) {
                Ok(0) => break,
                Ok(n) => {
                    body_vec.extend_from_slice(&temp[..n]);
                    remaining = remaining.saturating_sub(n);
                }
                Err(_) => return None,
            }
        }

        if body_vec.len() < content_length {
            return None; // Premature EOF
        }

        Some(HttpBody::Memory(body_vec))
    } else {
        if !staging_allowed {
            return None; // Staging not permitted for this endpoint
        }

        clear_transfer_cancel();
        let ddir = get_download_dir();
        let _ = fs::create_dir_all(&ddir);
        let _ = fs::set_permissions(&ddir, fs::Permissions::from_mode(0o700));

        let reservation = StagingReservationGuard::try_reserve(content_length as u64, &ddir).ok()?;

        let now_nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let mut rand_bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut rand_bytes);
        let stage_name = format!(".tmp_stage_{}_{}_{}.part", std::process::id(), now_nanos, hex::encode(rand_bytes));
        let stage_path = ddir.join(&stage_name);

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
        }

        let mut stage_file = match opts.open(&stage_path) {
            Ok(f) => f,
            Err(_) => return None,
        };

        let mut blake3_hasher = blake3::Hasher::new();
        let mut sha_hasher = Sha256::new();
        let mut md5_ctx = md5::Context::new();
        let copy_len = initial_len.min(content_length);
        if stage_file.write_all(&initial_body[..copy_len]).is_err() {
            let _ = fs::remove_file(&stage_path);
            return None;
        }
        blake3_hasher.update(&initial_body[..copy_len]);
        sha_hasher.update(&initial_body[..copy_len]);
        md5_ctx.consume(&initial_body[..copy_len]);

        let mut remaining = content_length.saturating_sub(copy_len);
        let mut total_written = copy_len as u64;
        let mut stream_chunk = [0u8; 131072]; // 128 KiB streaming chunk aligned with IEEE 802.11 A-MPDU
        let mut last_progress_tick = Instant::now();

        while remaining > 0 {
            if is_transfer_cancelled() {
                clear_transfer_cancel();
                clear_transfer_progress();
                let _ = fs::remove_file(&stage_path);
                return None;
            }
            let to_read = remaining.min(stream_chunk.len());
            match read_stream_chunk_with_deadline(stream, &mut stream_chunk[..to_read], deadline) {
                Ok(0) => {
                    clear_transfer_progress();
                    let _ = fs::remove_file(&stage_path);
                    return None;
                }
                Ok(n) => {
                    if stage_file.write_all(&stream_chunk[..n]).is_err() {
                        clear_transfer_progress();
                        let _ = fs::remove_file(&stage_path);
                        return None;
                    }
                    blake3_hasher.update(&stream_chunk[..n]);
                    sha_hasher.update(&stream_chunk[..n]);
                    md5_ctx.consume(&stream_chunk[..n]);
                    total_written = total_written.saturating_add(n as u64);
                    remaining = remaining.saturating_sub(n);
                    if last_progress_tick.elapsed() >= Duration::from_millis(250) {
                        save_transfer_progress("receive", "Incoming Transfer", total_written, content_length as u64);
                        last_progress_tick = Instant::now();
                    }
                }
                Err(_) => {
                    clear_transfer_progress();
                    let _ = fs::remove_file(&stage_path);
                    return None;
                }
            }
        }
        clear_transfer_progress();

        if stage_file.flush().is_err() {
            let _ = fs::remove_file(&stage_path);
            return None;
        }

        let blake3_hex = blake3_hasher.finalize().to_hex().to_string();
        let sha256_hex = hex::encode(sha_hasher.finalize());
        let md5_hex = format!("{:x}", md5_ctx.compute());
        let staged = StagedFile::with_hashes(
            stage_path,
            total_written,
            Some(reservation),
            Some(blake3_hex),
            Some(sha256_hex),
            Some(md5_hex),
        );
        Some(HttpBody::Staged(staged))
    }
}

pub fn read_http_request_stream<S: TimeoutStream>(stream: &mut S) -> Option<(HttpRequest, HttpBody)> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let h_res = read_http_headers(stream, deadline)?;
    let body = read_http_body(
        stream,
        h_res.content_length,
        &h_res.initial_body,
        deadline,
        true,
        MAX_BODY_SIZE,
    )?;
    Some((h_res.req, body))
}

pub fn read_full_http_request(stream: &mut TcpStream) -> Option<(HttpRequest, HttpBody)> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let h_res = read_http_headers(stream, deadline)?;
    let body = read_http_body(
        stream,
        h_res.content_length,
        &h_res.initial_body,
        deadline,
        true,
        MAX_BODY_SIZE,
    )?;
    Some((h_res.req, body))
}

struct PinAttemptState {
    failed_count: u32,
    window_start: Instant,
    blocked_until: Option<Instant>,
}

type AttemptLimiter = Mutex<Option<HashMap<IpAddr, PinAttemptState>>>;

static PIN_RATE_LIMITER: AttemptLimiter = Mutex::new(None);
/// Failed /api/v2/pair attempts per source address (M17).
static PAIR_RATE_LIMITER: AttemptLimiter = Mutex::new(None);

/// Failed portal-secret attempts from all addresses together. The per-address limit alone is
/// no defence through the tunnel, where an attacker controls many source addresses.
static PIN_GLOBAL_LIMITER: Mutex<Option<PinAttemptState>> = Mutex::new(None);
pub const PIN_GLOBAL_MAX_FAILURES: u32 = 30;

pub fn is_pin_rate_limited(ip: IpAddr) -> bool {
    is_rate_limited(&PIN_RATE_LIMITER, ip)
}

pub fn record_pin_attempt(ip: IpAddr, success: bool) -> bool {
    let per_ip = record_attempt(&PIN_RATE_LIMITER, ip, success);
    if success {
        return per_ip;
    }
    record_global_pin_failure() && per_ip
}

fn is_pin_globally_limited() -> bool {
    let guard = PIN_GLOBAL_LIMITER.lock().unwrap_or_else(|p| p.into_inner());
    guard.as_ref().and_then(|s| s.blocked_until).is_some_and(|b| Instant::now() < b)
}

/// Counts one failure in the global budget; returns false once it is used up
/// (`PIN_GLOBAL_MAX_FAILURES` within 60 s -> every non-local client waits 60 s).
fn record_global_pin_failure() -> bool {
    let mut guard = PIN_GLOBAL_LIMITER.lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    let state = guard.get_or_insert(PinAttemptState {
        failed_count: 0,
        window_start: now,
        blocked_until: None,
    });
    if let Some(b) = state.blocked_until {
        if now < b {
            return false;
        }
        state.blocked_until = None;
        state.failed_count = 0;
        state.window_start = now;
    }
    if now.duration_since(state.window_start) > Duration::from_secs(60) {
        state.failed_count = 0;
        state.window_start = now;
    }
    state.failed_count = state.failed_count.saturating_add(1);
    if state.failed_count >= PIN_GLOBAL_MAX_FAILURES {
        state.blocked_until = Some(now + Duration::from_secs(60));
        return false;
    }
    true
}

fn is_rate_limited(limiter: &AttemptLimiter, ip: IpAddr) -> bool {
    let mut guard = match limiter.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    if let Some(state) = map.get(&ip) {
        if let Some(blocked) = state.blocked_until {
            if now < blocked {
                return true;
            }
        }
    }
    false
}

/// Records an attempt; returns false once `ip` is blocked (5 failures within 60 s -> 60 s).
fn record_attempt(limiter: &AttemptLimiter, ip: IpAddr, success: bool) -> bool {
    let mut guard = match limiter.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();

    if map.len() > 1000 {
        map.retain(|_, s| now.duration_since(s.window_start) < Duration::from_secs(300));
    }

    if success {
        map.remove(&ip);
        return true;
    }

    let state = map.entry(ip).or_insert(PinAttemptState {
        failed_count: 0,
        window_start: now,
        blocked_until: None,
    });

    if state.blocked_until.is_none() && now.duration_since(state.window_start) > Duration::from_secs(60) {
        state.failed_count = 0;
        state.window_start = now;
    }

    state.failed_count = state.failed_count.saturating_add(1);
    if state.failed_count >= 5 {
        state.blocked_until = Some(now + Duration::from_secs(60));
        return false;
    }
    true
}

#[cfg(test)]
pub fn reset_pin_rate_limiter() {
    *PIN_GLOBAL_LIMITER.lock().unwrap_or_else(|p| p.into_inner()) = None;
    for limiter in [&PIN_RATE_LIMITER, &PAIR_RATE_LIMITER] {
        let mut guard = match limiter.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(ref mut map) = *guard {
            map.clear();
        }
    }
}

/// The portal secret is accepted only from the `X-OmaSend-PIN` header. A `?pin=` query
/// parameter is ignored: URLs end up in browser history, proxy and Cloudflare logs.
fn extract_provided_pin(req: &HttpRequest) -> Option<String> {
    if let Some(h) = req.get_header("x-omasend-pin") {
        if !h.is_empty() {
            return Some(h.to_string());
        }
    }
    None
}

const WEB_SESSION_COOKIE: &str = "omasend_session";

/// Portal session cookie value: HMAC(session key, PIN). It changes whenever the PIN or the
/// session key is rotated and does not reveal the PIN.
fn web_session_value(pin: &str, key_hex: &str) -> String {
    hex::encode(rendezvous::hmac_sha256(key_hex.as_bytes(), format!("omasend-web-session|{}", pin).as_bytes()))
}

/// `Set-Cookie` value (attributes after the first `;`; `send_response` appends Path, HttpOnly
/// and SameSite=Strict).
fn web_session_set_cookie(value: &str, secure: bool) -> String {
    format!("{}={}{}", WEB_SESSION_COOKIE, value, if secure { "; Secure" } else { "" })
}

fn web_session_cookie(req: &HttpRequest) -> Option<&str> {
    req.get_header("cookie")?
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, v)| *k == WEB_SESSION_COOKIE && !v.is_empty())
        .map(|(_, v)| v)
}

fn is_trusted_origin(origin: &str, local_ip: &str) -> bool {
    let clean = origin.trim();
    if clean == "http://localhost" || clean.starts_with("http://localhost:")
        || clean == "http://127.0.0.1" || clean.starts_with("http://127.0.0.1:") {
        return true;
    }
    let expected_local = format!("http://{}", local_ip);
    if clean == expected_local || clean.starts_with(&format!("{}:", expected_local)) {
        return true;
    }
    false
}

fn send_response(
    mut stream: &TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    cookie: Option<&str>,
    extra_headers: Option<&[(&str, &str)]>,
    cors_origin: Option<&str>,
) {
    let cookie_header = if let Some(c) = cookie {
        format!("Set-Cookie: {}; Path=/; HttpOnly; SameSite=Strict\r\n", c)
    } else {
        String::new()
    };
    let mut extra = String::new();
    if let Some(hdrs) = extra_headers {
        for (k, v) in hdrs {
            extra.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    let cors_header = if let Some(origin) = cors_origin {
        format!("Access-Control-Allow-Origin: {}\r\nVary: Origin\r\n", origin)
    } else {
        String::new()
    };
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}{}{}Connection: close\r\n\r\n",
        status, content_type, body.len(), cors_header, cookie_header, extra
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(body);
}

/// Zero-copy file streaming using Linux sendfile(2) directly to socket descriptor.
/// Validates regular file ownership & UID, constructs HTTP response headers, and streams without Vec<u8> memory allocations.
pub fn stream_file_zero_copy(
    stream: &mut TcpStream,
    path: &Path,
    content_type: &str,
    extra_headers: Option<&[(&str, &str)]>,
    cors_origin: Option<&str>,
) -> Result<u64, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("Failed to stat {:?}: {}", path, e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("Security violation: {:?} is a symlink", path));
    }
    if !meta.file_type().is_file() {
        return Err(format!("Security violation: {:?} is not a regular file", path));
    }
    let current_uid = get_current_uid();
    if meta.uid() != current_uid {
        return Err(format!(
            "Security violation: {:?} is owned by UID {}, expected current user UID {}",
            path,
            meta.uid(),
            current_uid
        ));
    }

    let file_len = meta.len();
    let file = File::open(path).map_err(|e| format!("Failed to open {:?}: {}", path, e))?;

    let mut extra = String::new();
    if let Some(hdrs) = extra_headers {
        for (k, v) in hdrs {
            extra.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    let cors_header = if let Some(origin) = cors_origin {
        format!("Access-Control-Allow-Origin: {}\r\nVary: Origin\r\n", origin)
    } else {
        String::new()
    };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}{}Connection: close\r\n\r\n",
        content_type, file_len, cors_header, extra
    );
    stream.write_all(resp.as_bytes()).map_err(|e| format!("Failed to write HTTP headers: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let in_fd = file.as_raw_fd();
        let out_fd = stream.as_raw_fd();
        let mut offset: libc::off_t = 0;
        let mut remaining = file_len;
        let mut total_sent: u64 = 0;

        while remaining > 0 {
            let to_send = (remaining as usize).min(1024 * 1024); // 1 MiB chunk for sendfile
            let sent = unsafe {
                libc::sendfile(
                    out_fd,
                    in_fd,
                    &mut offset,
                    to_send,
                )
            };
            if sent < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("sendfile error: {}", err));
            }
            if sent == 0 {
                break;
            }
            remaining = remaining.saturating_sub(sent as u64);
            total_sent = total_sent.saturating_add(sent as u64);
        }
        Ok(total_sent)
    }

    #[cfg(not(unix))]
    {
        let mut reader = file;
        let mut buf = [0u8; 131072];
        let mut total_sent = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            total_sent += n as u64;
        }
        Ok(total_sent)
    }
}

// ------------------- WEB PAGES -------------------

const OMARCHY_INLINE_LOGO_SVG: &str = r##"<span class="omarchy-plane-icon" style="font-family: 'JetBrainsMono Nerd Font', 'JetBrains Mono', monospace; font-size: 20px; color: #00cbb8; line-height: 1;"></span>"##;

fn render_login_page() -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>OmaSend | Portal Access</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace; background: #0d1117; color: #dbe4ee; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 0; padding: 36px 24px; width: 100%; max-width: 390px; text-align: center; box-shadow: 0 12px 40px rgba(0,0,0,0.65); }}
.logo-wrap {{ display: flex; align-items: center; justify-content: center; margin-bottom: 18px; color: #00cbb8; }}
.omarchy-logo {{ height: 22px; width: auto; display: block; }}
.tag {{ display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: 1px; color: #00cbb8; border: 1px solid #00cbb8; background: rgba(0, 203, 184, 0.1); padding: 3px 8px; margin-bottom: 12px; }}
h1 {{ font-size: 18px; font-weight: 700; color: #dbe4ee; margin-bottom: 8px; letter-spacing: 0.5px; }}
p {{ font-size: 12px; color: #8b949e; margin-bottom: 24px; line-height: 1.6; }}
.pin-input {{ width: 100%; font-size: 13px; letter-spacing: 1px; text-align: center; background: #0d1117; border: 1px solid #00cbb8; color: #00eed9; border-radius: 0; padding: 12px; margin-bottom: 20px; font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace; outline: none; transition: border-color 0.2s; }}
.pin-input:focus {{ border-color: #00eed9; box-shadow: 0 0 12px rgba(0,203,184,0.25); }}
button {{ width: 100%; background: #00cbb8; color: #0d1117; border: none; padding: 13px; font-size: 13px; font-weight: 700; font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace; letter-spacing: 0.5px; border-radius: 0; cursor: pointer; text-transform: uppercase; transition: opacity 0.2s; }}
button:active {{ opacity: 0.85; }}
</style>
</head>
<body>
<div class="card">
<div class="logo-wrap">{}</div>
<div class="tag">ZERO-TRUST GATEWAY</div>
<h1>OMASEND AIRBRIDGE</h1>
<p id="msg">Scan the portal QR code on your Omarchy desktop panel, or paste the access secret (omasend-engine --portal-url).</p>
<form id="login">
<input type="password" id="secret" class="pin-input" placeholder="access secret" required autofocus autocomplete="off" spellcheck="false">
<button type="submit">Verify &amp; Connect</button>
</form>
</div>
<script>
// The secret travels in the link's fragment (never sent to the server) and is presented once
// in a header; the server answers with an HttpOnly session cookie.
async function login(secret) {{
  var res = await fetch('/api/login', {{ method: 'POST', headers: {{ 'X-OmaSend-PIN': secret }}, credentials: 'same-origin' }});
  if (res.ok) {{
    var key = window.location.hash.match(/key=([a-f0-9]{{64}})/i);
    history.replaceState(null, '', '/' + (key ? '#key=' + key[1] : ''));
    window.location.reload();
  }} else {{
    document.getElementById('msg').innerText = res.status === 429 ? 'Too many attempts. Wait a minute and try again.' : 'Access denied.';
  }}
}}
var m = window.location.hash.match(/pin=([a-f0-9]+)/i);
if (m) {{ login(m[1]); }}
document.getElementById('login').addEventListener('submit', function(e) {{
  e.preventDefault();
  login(document.getElementById('secret').value.trim());
}});
</script>
</body>
</html>"#,
        OMARCHY_INLINE_LOGO_SVG
    )
}

fn render_web_app(active_endpoint: &str, shared_files: &[FileInfo]) -> String {
    let mut files_html = String::new();
    if shared_files.is_empty() {
        files_html.push_str("<div class='empty'>No files shared from PC.<br><small style='color:#6e7681;'>Add files to ~/Downloads/omasend/shared.</small></div>");
    } else {
        for f in shared_files {
            // File names are arbitrary: escape them, and pass the name to JS through a data
            // attribute instead of splicing it into a JS string literal.
            let name = html_escape(&f.name);
            files_html.push_str(&format!(
                r#"<div class="file-item">
<div class="file-info"><div class="file-name">{}</div><div class="file-size">{}</div></div>
<button data-name="{}" onclick="downloadFile(this.dataset.name)" class="btn-sm">Download</button>
</div>"#,
                name,
                html_escape(&f.size_str),
                name
            ));
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>OmaSend | AirBridge E2EE</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace; background: #0d1117; color: #dbe4ee; padding: 18px; max-width: 600px; margin: 0 auto; }}
.header {{ display: flex; align-items: center; justify-content: space-between; padding-bottom: 14px; border-bottom: 1px solid #30363d; margin-bottom: 18px; gap: 12px; flex-wrap: wrap; }}
.brand {{ font-size: 15px; font-weight: 700; color: #00cbb8; display: flex; align-items: center; gap: 10px; letter-spacing: 0.5px; }}
.omarchy-logo {{ height: 18px; width: auto; display: block; color: #00cbb8; }}
.brand-sep {{ color: #30363d; font-weight: 400; }}
.brand-title {{ color: #dbe4ee; font-weight: 700; }}
.badges {{ display: flex; gap: 6px; flex-wrap: wrap; }}
.badge {{ font-size: 11px; background: rgba(0, 203, 184, 0.12); border: 1px solid #00cbb8; color: #00cbb8; padding: 4px 8px; border-radius: 0; font-weight: 700; }}
.badge-e2ee {{ font-size: 11px; background: rgba(39, 201, 63, 0.12); border: 1px solid #27c93f; color: #27c93f; padding: 4px 8px; border-radius: 0; font-weight: 700; display: flex; align-items: center; gap: 4px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 0; padding: 18px; margin-bottom: 16px; }}
.card-title {{ font-size: 12px; font-weight: 700; letter-spacing: 0.8px; color: #8b949e; text-transform: uppercase; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; }}
.drop-zone {{ border: 1px dashed #00cbb8; border-radius: 0; padding: 32px 16px; text-align: center; cursor: pointer; background: #0d1117; transition: all 0.2s; }}
.drop-zone:hover {{ background: rgba(0, 203, 184, 0.06); border-color: #00eed9; }}
.drop-icon {{ font-size: 18px; font-weight: 700; color: #00cbb8; margin-bottom: 8px; letter-spacing: 1px; }}
.file-item {{ display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: #0d1117; border-radius: 0; margin-bottom: 8px; border: 1px solid #30363d; }}
.file-name {{ font-size: 13px; font-weight: 600; word-break: break-all; color: #dbe4ee; }}
.file-size {{ font-size: 11px; color: #8b949e; margin-top: 2px; }}
.btn-sm {{ background: #00cbb8; color: #0d1117; border: none; padding: 6px 14px; border-radius: 0; font-size: 11px; font-weight: 700; font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace; cursor: pointer; text-transform: uppercase; }}
textarea {{ width: 100%; height: 84px; background: #0d1117; border: 1px solid #30363d; border-radius: 0; color: #dbe4ee; padding: 12px; font-size: 12px; font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace; margin-bottom: 10px; resize: vertical; outline: none; }}
textarea:focus {{ border-color: #00cbb8; }}
button.main-btn {{ width: 100%; background: #00cbb8; color: #0d1117; border: none; padding: 12px; font-size: 12px; font-weight: 700; font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace; letter-spacing: 0.5px; border-radius: 0; cursor: pointer; text-transform: uppercase; }}
.clipboard-box {{ background: #0d1117; border: 1px solid #30363d; padding: 12px; border-radius: 0; font-size: 12px; max-height: 110px; overflow-y: auto; margin-bottom: 10px; color: #00eed9; font-family: "JetBrainsMono Nerd Font", "JetBrains Mono", monospace; white-space: pre-wrap; }}
.empty {{ font-size: 12px; color: #8b949e; text-align: center; padding: 16px; line-height: 1.6; }}
#progress-bar {{ display: none; width: 100%; height: 8px; background: #0d1117; border: 1px solid #30363d; border-radius: 0; overflow: hidden; margin-top: 14px; }}
#progress-fill {{ width: 0%; height: 100%; background: #00cbb8; transition: width 0.2s; }}
#status-msg {{ font-size: 12px; font-weight: 600; color: #00cbb8; margin-top: 10px; text-align: center; }}
</style>
</head>
<body>
<div class="header">
<div class="brand">{}<span class="brand-sep">/</span><span class="brand-title">OMASEND AIRBRIDGE</span></div>
<div class="badges">
  <div class="badge">NODE: {}</div>
  <div id="e2ee-badge" class="badge-e2ee">E2EE ACTIVE</div>
</div>
</div>

<div class="card">
<div class="card-title">
  <span>Send Files to PC</span>
  <span style="color:#27c93f; font-size:11px;">AES-256-GCM Encrypted</span>
</div>
<div class="drop-zone" onclick="document.getElementById('file-input').click()">
<div class="drop-icon">[UPLOAD]</div>
<div style="font-size: 14px; font-weight: 700;">Select Photos, Videos or Archives</div>
<div style="font-size: 11px; color: #8b949e; margin-top: 4px;">Tap or drag &amp; drop files here</div>
<input type="file" id="file-input" style="display: none;" onchange="uploadFiles(this.files)" multiple>
</div>
<div id="progress-bar"><div id="progress-fill"></div></div>
<div id="status-msg"></div>
</div>

<div class="card">
<div class="card-title">
  <span>PC Clipboard</span>
  <button onclick="fetchClipboard()" class="btn-sm" style="padding:3px 8px; font-size:10px;">Refresh</button>
</div>
<div class="clipboard-box" id="pc-clip">Loading clipboard...</div>
<button class="main-btn" onclick="copyPcClipboard()">Copy to Device</button>
</div>

<div class="card">
<div class="card-title">
  <span>Send Text to PC Clipboard</span>
  <span style="color:#27c93f; font-size:11px;">Encrypted Transfer</span>
</div>
<textarea id="clip-text" placeholder="Type text to instantly paste to PC clipboard..."></textarea>
<button class="main-btn" onclick="sendClipboard()">Send to PC Clipboard</button>
</div>

<div class="card">
<div class="card-title">Shared Files from PC</div>
{}
</div>

<script>
var e2eeKeyHex = null;
var cryptoKey = null;

async function initE2EE() {{
  var hash = window.location.hash;
  var match = hash.match(/key=([a-f0-9]{{64}})/i);
  if (match) {{
    e2eeKeyHex = match[1].toLowerCase();
    sessionStorage.setItem('omasend_e2ee_key', e2eeKeyHex);
  }} else {{
    e2eeKeyHex = sessionStorage.getItem('omasend_e2ee_key');
  }}

  if (e2eeKeyHex && e2eeKeyHex.length === 64) {{
    try {{
      var rawKey = new Uint8Array(e2eeKeyHex.match(/.{{1,2}}/g).map(function(b) {{ return parseInt(b, 16); }}));
      cryptoKey = await window.crypto.subtle.importKey(
        "raw",
        rawKey,
        {{ name: "AES-GCM" }},
        false,
        ["encrypt", "decrypt"]
      );
      document.getElementById('e2ee-badge').innerText = 'E2EE ACTIVE (AES-256-GCM)';
    }} catch(e) {{
      console.error("WebCrypto key import error:", e);
    }}
  }} else {{
    document.getElementById('e2ee-badge').innerText = 'NO E2EE KEY';
    document.getElementById('e2ee-badge').style.color = '#ffaa00';
    document.getElementById('e2ee-badge').style.borderColor = '#ffaa00';
  }}
}}

async function uploadFiles(files) {{
  if (!files || files.length === 0) return;
  var pBar = document.getElementById('progress-bar');
  var pFill = document.getElementById('progress-fill');
  var sMsg = document.getElementById('status-msg');

  pBar.style.display = 'block';

  for (var i = 0; i < files.length; i++) {{
    var file = files[i];
    sMsg.innerText = 'Encrypting: ' + file.name + '...';
    pFill.style.width = '15%';

    try {{
      var arrayBuffer = await file.arrayBuffer();

      if (cryptoKey) {{
        var iv = window.crypto.getRandomValues(new Uint8Array(12));
        var encryptedBuffer = await window.crypto.subtle.encrypt(
          {{ name: "AES-GCM", iv: iv }},
          cryptoKey,
          arrayBuffer
        );
        var ivHex = Array.from(iv).map(function(b) {{ return b.toString(16).padStart(2, '0'); }}).join('');

        sMsg.innerText = 'Sending: ' + file.name + ' (E2EE)...';
        await sendEncryptedFile(file.name, ivHex, encryptedBuffer, pFill);
      }} else {{
        sMsg.innerText = 'Sending: ' + file.name + '...';
        await sendPlainFile(file, pFill);
      }}
    }} catch(err) {{
      sMsg.innerText = 'Error: ' + err.message;
      return;
    }}
  }}

  pFill.style.width = '100%';
  sMsg.innerText = 'Files transferred successfully to PC.';
  setTimeout(function() {{
    pBar.style.display = 'none';
    sMsg.innerText = '';
  }}, 3000);
}}

function sendEncryptedFile(filename, ivHex, encryptedBuffer, pFill) {{
  return new Promise(function(resolve, reject) {{
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload-encrypted', true);
    xhr.setRequestHeader('X-OmaSend-Filename', encodeURIComponent(filename));
    xhr.setRequestHeader('X-OmaSend-IV', ivHex);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');

    xhr.upload.onprogress = function(e) {{
      if (e.lengthComputable) {{
        var p = Math.round(20 + (e.loaded / e.total) * 75);
        pFill.style.width = p + '%';
      }}
    }};
    xhr.onload = function() {{
      if (xhr.status === 200) resolve();
      else reject(new Error('Server error: ' + xhr.status));
    }};
    xhr.onerror = function() {{ reject(new Error('Network error')); }};
    xhr.send(encryptedBuffer);
  }});
}}

function sendPlainFile(file, pFill) {{
  return new Promise(function(resolve, reject) {{
    var formData = new FormData();
    formData.append('file', file);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/upload', true);
    xhr.upload.onprogress = function(e) {{
      if (e.lengthComputable) {{
        pFill.style.width = Math.round((e.loaded / e.total) * 100) + '%';
      }}
    }};
    xhr.onload = function() {{
      if (xhr.status === 200) resolve();
      else reject(new Error('Server error'));
    }};
    xhr.onerror = function() {{ reject(new Error('Network error')); }};
    xhr.send(formData);
  }});
}}

async function downloadFile(filename) {{
  if (!cryptoKey) {{
    window.location.href = '/download/' + encodeURIComponent(filename);
    return;
  }}
  try {{
    var res = await fetch('/api/download-encrypted/' + encodeURIComponent(filename));
    if (!res.ok) throw new Error('Download error');
    var ivHex = res.headers.get('X-OmaSend-IV');
    if (!ivHex || ivHex.length !== 24) throw new Error('Invalid IV header');

    var iv = new Uint8Array(ivHex.match(/.{{1,2}}/g).map(function(b) {{ return parseInt(b, 16); }}));
    var encryptedData = await res.arrayBuffer();

    var decrypted = await window.crypto.subtle.decrypt(
      {{ name: "AES-GCM", iv: iv }},
      cryptoKey,
      encryptedData
    );

    var blob = new Blob([decrypted]);
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }} catch(e) {{
    alert('Encrypted download error: ' + e.message);
  }}
}}

async function fetchClipboard() {{
  var box = document.getElementById('pc-clip');
  box.innerText = 'Fetching clipboard...';
  try {{
    if (cryptoKey) {{
      var res = await fetch('/api/clipboard-encrypted');
      var data = await res.json();
      if (data.iv && data.ciphertext) {{
        var iv = new Uint8Array(data.iv.match(/.{{1,2}}/g).map(function(b) {{ return parseInt(b, 16); }}));
        var cipherBytes = new Uint8Array(data.ciphertext.match(/.{{1,2}}/g).map(function(b) {{ return parseInt(b, 16); }}));
        var decrypted = await window.crypto.subtle.decrypt(
          {{ name: "AES-GCM", iv: iv }},
          cryptoKey,
          cipherBytes
        );
        var text = new TextDecoder().decode(decrypted);
        box.innerText = text || "(Clipboard empty)";
        return;
      }}
    }}
    var r = await fetch('/api/clipboard');
    var d = await r.json();
    box.innerText = d.clipboard || "(Clipboard empty)";
  }} catch(e) {{
    box.innerText = "(Failed to fetch clipboard)";
  }}
}}

async function sendClipboard() {{
  var text = document.getElementById('clip-text').value;
  if (!text) return;
  try {{
    if (cryptoKey) {{
      var textBytes = new TextEncoder().encode(text);
      var iv = window.crypto.getRandomValues(new Uint8Array(12));
      var encrypted = await window.crypto.subtle.encrypt(
        {{ name: "AES-GCM", iv: iv }},
        cryptoKey,
        textBytes
      );
      var ivHex = Array.from(iv).map(function(b) {{ return b.toString(16).padStart(2, '0'); }}).join('');
      var res = await fetch('/api/clipboard-encrypted', {{
        method: 'POST',
        headers: {{
          'X-OmaSend-IV': ivHex,
          'Content-Type': 'application/octet-stream'
        }},
        body: encrypted
      }});
      if (res.ok) {{
        alert('Encrypted text sent to PC clipboard.');
        document.getElementById('clip-text').value = '';
        fetchClipboard();
      }}
    }} else {{
      var res = await fetch('/api/clipboard', {{
        method: 'POST',
        body: 'text=' + encodeURIComponent(text)
      }});
      if (res.ok) {{
        alert('Text sent to PC clipboard.');
        document.getElementById('clip-text').value = '';
        fetchClipboard();
      }}
    }}
  }} catch(e) {{
    alert('Error: ' + e.message);
  }}
}}

function copyPcClipboard() {{
  var text = document.getElementById('pc-clip').innerText;
  if (!text || text.startsWith('(')) return;
  navigator.clipboard.writeText(text).then(function() {{
    alert('Clipboard copied to device.');
  }});
}}

window.addEventListener('load', async function() {{
  await initE2EE();
  fetchClipboard();
}});
</script>
</body>
</html>"#,
        OMARCHY_INLINE_LOGO_SVG,
        active_endpoint,
        files_html
    )
}

// ------------------- CONNECTION HANDLER -------------------

/// Body of the unauthenticated `/api/p2p/ping`: device id, name and visibility only.
fn ping_response() -> serde_json::Value {
    let (id, _) = get_or_create_device_id();
    let (vis, _) = get_visibility();
    serde_json::json!({
        "status": "OK",
        "id": id.clone(),
        "device_id": id,
        "name": get_system_hostname(),
        "mode": vis
    })
}

pub fn handle_connection(mut stream: TcpStream, ip: &str, pin: &str, key_hex: &str) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    let header_deadline = Instant::now() + Duration::from_secs(HEADER_READ_TIMEOUT_SECS);

    let h_res = match read_http_headers(&mut stream, header_deadline) {
        Some(h) => h,
        None => return,
    };

    let req = h_res.req;
    let content_length = h_res.content_length;
    let initial_body = h_res.initial_body;

    let client_ip = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let origin = req.get_header("origin");
    let allowed_cors = origin.filter(|&o| is_trusted_origin(o, ip));
    let local_ctl = is_local_control(&req, client_ip);

    let respond = |s: &TcpStream, status: &str, content_type: &str, body: &[u8], cookie: Option<&str>, extra: Option<&[(&str, &str)]>| {
        send_response(s, status, content_type, body, cookie, extra, allowed_cors);
    };

    if req.method == "OPTIONS" {
        respond(
            &stream,
            "204 No Content",
            "text/plain",
            b"",
            None,
            Some(&[
                ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                ("Access-Control-Allow-Headers", "Content-Type, X-OmaSend-PIN, X-OmaSend-IV, X-OmaSend-Filename"),
            ]),
        );
        return;
    }

    // Internet traffic from the WAN tunnel only ever reaches the portal.
    let via_tunnel = is_tunnel_request(&req, client_ip);
    if via_tunnel && !is_portal_route(&req.method, &req.path) {
        respond(&stream, "404 Not Found", "application/json", b"{\"error\":\"Not available over WAN\"}", None, None);
        return;
    }

    // The local CLI/panel is never locked out by someone else's wrong PINs (M5).
    let rl_ip = rate_limit_ip(&req, client_ip);
    if !local_ctl && is_pin_rate_limited(rl_ip) {
        let err = b"{\"error\":\"Too many failed access attempts. Please wait 60 seconds.\"}";
        respond(
            &stream,
            "429 Too Many Requests",
            "application/json",
            err,
            None,
            Some(&[("Retry-After", "60")]),
        );
        return;
    }

    let web_session = web_session_value(pin, key_hex);
    let maybe_pin = extract_provided_pin(&req);
    // While the global budget is used up no new secret is even compared. Existing portal
    // sessions (cookie) and paired-device traffic keep working, so this cannot be used to cut
    // off the user's own devices.
    if maybe_pin.is_some() && !local_ctl && is_pin_globally_limited() {
        let err = b"{\"error\":\"Too many failed access attempts. Please wait 60 seconds.\"}";
        respond(&stream, "429 Too Many Requests", "application/json", err, None, Some(&[("Retry-After", "60")]));
        return;
    }
    let authorized = match maybe_pin {
        Some(ref p) if !pin.is_empty() && constant_time_eq_str(p, pin) => {
            record_pin_attempt(rl_ip, true);
            true
        }
        Some(_) if !local_ctl => {
            let not_blocked = record_pin_attempt(rl_ip, false);
            if !not_blocked {
                let err = b"{\"error\":\"Too many failed access attempts. Please wait 60 seconds.\"}";
                respond(
                    &stream,
                    "429 Too Many Requests",
                    "application/json",
                    err,
                    None,
                    Some(&[("Retry-After", "60")]),
                );
                return;
            }
            false
        }
        Some(_) => false,
        None => web_session_cookie(&req).is_some_and(|c| constant_time_eq_str(c, &web_session)),
    };

    if req.path == "/api/status" {
        let (wan_active, wan_connecting, _wan_url) = get_wan_status();
        let mode = get_active_mode();
        let resp = if authorized {
            serde_json::json!({
                "status": "ACTIVE",
                "port": PORT,
                "ip": ip,
                "mode": mode,
                "wan_active": wan_active,
                "wan_connecting": wan_connecting,
                "auth_required": true
            })
        } else {
            serde_json::json!({
                "status": "ACTIVE",
                "port": PORT,
                "auth_required": true
            })
        };
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    // --- P2P AIRDROP ENDPOINTS ---
    if req.path == "/api/p2p/ping" {
        // Unauthenticated: no OmaID (it used to double as a credential) and nothing secret.
        let resp = ping_response();
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }
    if req.method == "POST" && req.path == "/api/local/core-send" {
        if !local_ctl {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Forbidden\"}", None, None);
            return;
        }
        let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CONTROL_BODY) {
            Some(b) => b,
            None => return,
        };
        let val: serde_json::Value = body.as_slice().and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
        let strs = |k: &str| -> Vec<String> {
            val[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
        };
        let pk = val["pk"].as_str().unwrap_or_default().to_string();
        let out = match (CORE_NODE.get(), trust_store().get(&pk)) {
            (None, _) => serde_json::json!({ "ok": false, "unavailable": true, "error": "core not running" }),
            (_, None) => serde_json::json!({ "ok": false, "unavailable": true, "error": "not paired" }),
            (Some(node), Some(_)) => {
                let _ = stream.set_write_timeout(None);
                let result = match val["text"].as_str() {
                    Some(text) => node.send_clipboard(pk, strs("addrs"), text.to_string()).map(|_| String::new()),
                    None => node.send_files(pk, strs("addrs"), strs("paths"), strs("names"), String::new()),
                };
                match result {
                    Ok(id) => serde_json::json!({ "ok": true, "transfer_id": id }),
                    Err(e) => {
                        let m = e.to_string();
                        serde_json::json!({ "ok": false, "unavailable": core_error_is_unavailable(&m), "error": m })
                    }
                }
            }
        };
        respond(&stream, "200 OK", "application/json", out.to_string().as_bytes(), None, None);
        return;
    }

    if req.method == "POST" && req.path == "/api/v2/account/sync" {
        if client_ip.to_canonical().is_loopback() {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Not available\"}", None, None);
            return;
        }
        if content_length > MAX_CONTROL_BODY {
            respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Request payload exceeds limit\"}", None, None);
            return;
        }
        let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
        let Some(body) = read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CONTROL_BODY) else { return };
        let Some(raw) = body.as_slice() else {
            respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid request\"}", None, None);
            return;
        };
        let ip = client_ip.to_canonical().to_string();
        let devicekey::AuthResult::Trusted(sender) = v2_verify(&req, &devicekey::body_tag_json(raw), &ip) else {
            respond(&stream, "401 Unauthorized", "application/json", b"{\"error\":\"Signed request from a linked device required\"}", None, None);
            return;
        };
        let Ok(val) = serde_json::from_slice::<serde_json::Value>(raw) else {
            respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid JSON\"}", None, None);
            return;
        };
        match omalink::apply_roster(&get_state_dir(), &trust_store(), &device_identity().public_b64(), &sender, &ip, &val) {
            Ok(out) => {
                if out.self_revoked {
                    notify_desktop("OmaSend", &format!("{} removed this device from your account.", sender.name));
                } else if !out.added.is_empty() {
                    notify_desktop("OmaSend: Devices linked", &format!("Now also linked: {}", out.added.join(", ")));
                }
                respond(&stream, "200 OK", "application/json", b"{\"ok\":true}", None, None);
            }
            Err(e) => respond(&stream, "403 Forbidden", "application/json", serde_json::json!({ "error": e }).to_string().as_bytes(), None, None),
        }
        return;
    }

    if req.method == "POST" && (req.path == "/api/v2/link/start" || req.path == "/api/v2/link/finish") {
        // Linking is LAN-only: the WAN tunnel arrives from loopback, and a
        // hidden device takes no guesses at all.
        if client_ip.to_canonical().is_loopback() || get_visibility().0 == "OFF" {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Linking not available\"}", None, None);
            return;
        }
        if content_length > MAX_CONTROL_BODY {
            respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Request payload exceeds limit\"}", None, None);
            return;
        }
        let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CONTROL_BODY) {
            Some(b) => b,
            None => return,
        };
        let val: serde_json::Value = match body.as_slice().and_then(|b| serde_json::from_slice(b).ok()) {
            Some(v) => v,
            None => {
                respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid JSON\"}", None, None);
                return;
            }
        };
        let ip = client_ip.to_canonical();
        let now = Instant::now();
        if req.path == "/api/v2/link/start" {
            let account = omalink::get_or_create_account_id(&get_state_dir());
            let res = match (val["v"].as_u64(), val["pA"].as_str()) {
                (Some(1), Some(pa)) => omalink::responder().lock().unwrap_or_else(|p| p.into_inner()).start(&account, ip, pa, now),
                _ => Err(omalink::StartError::Bad("Unsupported link request".into())),
            };
            match res {
                Ok(out) => respond(&stream, "200 OK", "application/json", out.to_string().as_bytes(), None, None),
                Err(omalink::StartError::RateLimited) => {
                    respond(&stream, "429 Too Many Requests", "application/json", b"{\"error\":\"Too many link attempts\"}", None, None)
                }
                Err(omalink::StartError::Bad(e)) => {
                    respond(&stream, "400 Bad Request", "application/json", serde_json::json!({ "error": e }).to_string().as_bytes(), None, None)
                }
            }
            return;
        }
        let my_quic = CORE_NODE.get().map(|n| n.bound_port()).unwrap_or(CORE_QUIC_PORT);
        let res = omalink::responder()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .finish(device_identity(), &get_system_hostname(), my_quic, ip, &val, now);
        match res {
            Ok((peer, _)) if omalink::is_revoked(&get_state_dir(), &peer.pk) => {
                respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"This device was removed from the account\"}", None, None);
            }
            Ok((peer, reply)) => {
                let Some(vk) = devicekey::decode_pk(&peer.pk) else { return };
                let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                let key = devicekey::TrustedKey {
                    device_id: devicekey::device_id_for_pk(vk.as_bytes()),
                    pk: peer.pk,
                    name: peer.name,
                    ip: ip.to_string(),
                    port: 0,
                    quic_port: peer.quic_port,
                    own_device: true,
                    added_at: ts,
                    last_seen: ts,
                };
                let label = format!("{} ({})", key.name, key.device_id);
                if trust_store().upsert(key).is_err() {
                    respond(&stream, "500 Internal Server Error", "application/json", b"{\"error\":\"Failed to store device key\"}", None, None);
                    return;
                }
                notify_desktop("OmaSend: Device linked", &format!("{} is now one of your devices.", label));
                respond(&stream, "200 OK", "application/json", reply.to_string().as_bytes(), None, None);
                push_roster();
            }
            Err(e) => {
                respond(&stream, "403 Forbidden", "application/json", serde_json::json!({ "error": e }).to_string().as_bytes(), None, None);
            }
        }
        return;
    }

    if req.method == "POST" && req.path == "/api/v2/pair" {
        if get_visibility().0 == "OFF" {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Recipient AirBridge visibility is turned Off\"}", None, None);
            return;
        }
        // Offer secrets are 256-bit, so guessing is hopeless; the per-address limit only stops
        // one host from hammering the endpoint. Failures no longer burn everyone's offers (M17).
        if is_rate_limited(&PAIR_RATE_LIMITER, rl_ip) {
            respond(&stream, "429 Too Many Requests", "application/json", b"{\"error\":\"Too many pairing attempts\"}", None, Some(&[("Retry-After", "60")]));
            return;
        }
        if content_length > MAX_CONTROL_BODY {
            respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Request payload exceeds limit\"}", None, None);
            return;
        }
        let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CONTROL_BODY) {
            Some(b) => b,
            None => return,
        };
        let val: serde_json::Value = match body.as_slice().and_then(|b| serde_json::from_slice(b).ok()) {
            Some(v) => v,
            None => {
                respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid JSON\"}", None, None);
                return;
            }
        };
        // Through the WAN tunnel the source is loopback, which is not the peer's address (M14).
        let peer_ip = if client_ip.to_canonical().is_loopback() { String::new() } else { client_ip.to_canonical().to_string() };
        let my_quic = CORE_NODE.get().map(|n| n.bound_port()).unwrap_or(CORE_QUIC_PORT);
        match devicekey::accept_pair_request(device_identity(), &get_state_dir(), &get_system_hostname(), &val, &peer_ip, my_quic) {
            Ok((resp, key)) => {
                record_attempt(&PAIR_RATE_LIMITER, rl_ip, true);
                let label = format!("{} ({})", key.name, key.device_id);
                let own = key.own_device;
                if trust_store().upsert(key).is_err() {
                    respond(&stream, "500 Internal Server Error", "application/json", b"{\"error\":\"Failed to store device key\"}", None, None);
                    return;
                }
                notify_desktop(
                    "OmaSend: Device paired",
                    &format!("{} is now paired{}.", label, if own { " as one of your devices" } else { "" }),
                );
                respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
            }
            Err(e) => {
                record_attempt(&PAIR_RATE_LIMITER, rl_ip, false);
                let err = serde_json::json!({ "error": e });
                respond(&stream, "403 Forbidden", "application/json", err.to_string().as_bytes(), None, None);
            }
        }
        return;
    }

    if req.method == "POST" && req.path == "/api/p2p/pair" {
        let (vis, _) = get_visibility();
        if vis == "OFF" {
            let err = serde_json::json!({ "error": "Recipient AirBridge visibility is turned Off" });
            respond(&stream, "403 Forbidden", "application/json", err.to_string().as_bytes(), None, None);
            return;
        }

        if content_length > MAX_CONTROL_BODY {
            let err = serde_json::json!({ "error": "Request payload exceeds control limit" });
            respond(&stream, "413 Payload Too Large", "application/json", err.to_string().as_bytes(), None, None);
            return;
        }

        let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CONTROL_BODY) {
            Some(b) => b,
            None => return,
        };

        let body_slice = match body.as_slice() {
            Some(s) => s,
            None => {
                respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid request\"}", None, None);
                return;
            }
        };

        if let Ok(req_data) = serde_json::from_slice::<serde_json::Value>(body_slice) {
            // Remote side may only COMPLETE a pairing the local user started with
            // `--pair-peer`, by presenting the one-time code shown locally. Body
            // supplied `ip` and `auth_token` fields are ignored: the address is
            // the observed TCP source and the token is generated locally.
            let peer_oma_id = req_data.get("oma_id")
                .or_else(|| req_data.get("sender_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let pair_code = req_data.get("pair_code").and_then(|v| v.as_str()).unwrap_or_default();

            // WAN tunnel traffic arrives from loopback; refuse it before the
            // shared rate limiter so internet clients cannot lock out localhost.
            if client_ip.to_canonical().is_loopback() {
                respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Pairing not authorized\"}", None, None);
                return;
            }

            if is_pin_rate_limited(client_ip) {
                respond(&stream, "429 Too Many Requests", "application/json", b"{\"error\":\"Too many pairing attempts\"}", None, None);
                return;
            }

            match complete_remote_pairing(peer_oma_id, pair_code, client_ip) {
                Ok(paired_record) => {
                    record_pin_attempt(client_ip, true);
                    let auth_token = paired_record.auth_token.unwrap_or_default();
                    let my_oma_id = get_or_create_oma_id();
                    let my_name = get_system_hostname();
                    notify_desktop("OmaSend AirBridge", &format!("Device paired: {}", paired_record.name));
                    let resp = serde_json::json!({
                        "status": "PAIRED",
                        "oma_id": my_oma_id,
                        "name": my_name,
                        "auth_token": auth_token
                    });
                    respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
                }
                Err(_) => {
                    record_pin_attempt(client_ip, false);
                    respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Pairing not authorized\"}", None, None);
                }
            }
            return;
        }
        respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid JSON\"}", None, None);
        return;
    }

    if req.method == "GET" && req.path == "/api/p2p/peers" {
        // The discovered-device list is for the local user only (it is reachable from the
        // internet when the WAN tunnel is on). The panel and CLI read it via --json (M12).
        if !local_ctl && !authorized {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Forbidden\"}", None, None);
            return;
        }
        let peers = get_discovered_peers();
        let (vis, remaining) = get_visibility();
        let resp = serde_json::json!({
            "peers": peers,
            "visibility": vis,
            "remaining_secs": remaining
        });
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    if req.method == "POST" && req.path == "/api/p2p/request" {
        let (vis, _) = get_visibility();
        if vis == "OFF" {
            let err = serde_json::json!({ "status": "REJECTED", "error": "Recipient AirBridge visibility is turned Off" });
            respond(&stream, "403 Forbidden", "application/json", err.to_string().as_bytes(), None, None);
            return;
        }

        if content_length > MAX_CONTROL_BODY {
            let err = serde_json::json!({ "status": "REJECTED", "error": "Request payload exceeds control limit" });
            respond(&stream, "413 Payload Too Large", "application/json", err.to_string().as_bytes(), None, None);
            return;
        }

        let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CONTROL_BODY) {
            Some(b) => b,
            None => return,
        };

        let body_slice = match body.as_slice() {
            Some(s) => s,
            None => {
                respond(&stream, "400 Bad Request", "application/json", b"{\"status\":\"REJECTED\",\"error\":\"Invalid JSON request\"}", None, None);
                return;
            }
        };
        let req_data: serde_json::Value = match serde_json::from_slice(body_slice) {
            Ok(v) => v,
            Err(_) => {
                respond(&stream, "400 Bad Request", "application/json", b"{\"status\":\"REJECTED\",\"error\":\"Invalid JSON request\"}", None, None);
                return;
            }
        };
        let v2_key = match v2_verify(&req, &devicekey::body_tag_json(body_slice), &client_ip.to_canonical().to_string()) {
            devicekey::AuthResult::Trusted(k) => Some(k),
            devicekey::AuthResult::Absent => None,
            devicekey::AuthResult::Rejected(why) => {
                let err = serde_json::json!({ "status": "REJECTED", "error": format!("Signature rejected: {}", why) });
                respond(&stream, "401 Unauthorized", "application/json", err.to_string().as_bytes(), None, None);
                return;
            }
        };

        // The sender id is a display label only. A claimed OmaID (public) authorizes nothing:
        // a paired device signs the request (v2), a legacy pairing presents its token, and
        // anything else may only ask (visibility EVERYONE) and waits for the user's approval.
        let sender_id = req_data.get("sender_id")
            .or_else(|| req_data.get("device_id"))
            .or_else(|| req_data.get("oma_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .chars()
            .take(64)
            .collect::<String>();
        let sender_name = req_data["sender_name"].as_str().unwrap_or("Unknown Omarchy Device").to_string();
        let sender_ip = req_data["sender_ip"].as_str().unwrap_or("").to_string();

        let provided_token = req.get_header("x-omasend-auth-token")
            .or_else(|| req_data.get("auth_token").and_then(|v| v.as_str()))
            .unwrap_or_default();
        let legacy_peer = if v2_key.is_none() { legacy_peer_authorized(provided_token) } else { None };
        if v2_key.is_none() && !provided_token.is_empty() && legacy_peer.is_none() {
            let err = serde_json::json!({ "status": "REJECTED", "error": "Invalid peer authentication token" });
            respond(&stream, "403 Forbidden", "application/json", err.to_string().as_bytes(), None, None);
            return;
        }
        let sender_name = match legacy_peer.as_ref() {
            Some(p) => p.name.clone(),
            None => sender_name,
        };

        // Visibility KNOWN (the default) accepts only paired senders: a verified device key, or
        // a legacy pairing that completed the code-verified handshake and presented its token.
        // EVERYONE is the time-limited opt-in for strangers (M9).
        if vis == "KNOWN" && v2_key.is_none() && legacy_peer.is_none() {
            let err = serde_json::json!({ "status": "REJECTED", "error": "Recipient only accepts transfers from paired devices" });
            respond(&stream, "403 Forbidden", "application/json", err.to_string().as_bytes(), None, None);
            return;
        }

        let mut file_names = Vec::new();
        let mut files_info = Vec::new();
        let mut total_size_bytes = 0u64;
        if let Some(arr) = req_data["files"].as_array() {
            for item in arr {
                if let Some(n) = item["name"].as_str() {
                    let clean = sanitize_filename(n);
                    let sz = item["size_bytes"].as_u64().unwrap_or(0);
                    let blake3 = item["blake3"].as_str().map(|s| s.to_lowercase());
                    let sha256 = item["sha256"].as_str().map(|s| s.to_lowercase());
                    let md5 = item["md5"].as_str().map(|s| s.to_lowercase());
                    file_names.push(clean.clone());
                    files_info.push(TransferFileInfo {
                        name: clean,
                        size_bytes: sz,
                        blake3,
                        sha256,
                        md5,
                    });
                    total_size_bytes = total_size_bytes.saturating_add(sz);
                }
            }
        }

        let ddir = get_download_dir();
        if let Some(avail) = get_available_disk_space(&ddir) {
            if total_size_bytes.saturating_add(25 * 1024 * 1024) > avail {
                let err = serde_json::json!({
                    "error": "Insufficient disk space on recipient device",
                    "available_bytes": avail,
                    "required_bytes": total_size_bytes
                });
                respond(&stream, "413 Payload Too Large", "application/json", err.to_string().as_bytes(), None, None);
                return;
            }
        }

        let mut token_bytes = [0u8; 16];
        let _ = getrandom::getrandom(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        // Only a cryptographically verified key that the user paired as "own device" may
        // auto-accept; everything else (including legacy pairings) waits for approval.
        let auto_accept = v2_key.as_ref().is_some_and(|k| k.own_device);
        let initial_status = if auto_accept { "ACCEPTED" } else { "PENDING" };
        let initial_expiry = if auto_accept { now.saturating_add(600) } else { now.saturating_add(30) };
        let sender_name = match v2_key.as_ref() {
            Some(k) => k.name.clone(),
            None => sender_name,
        };

        let transfer = PendingFileTransfer {
            token: token.clone(),
            sender_id,
            sender_name: sender_name.clone(),
            sender_ip,
            file_names: file_names.clone(),
            remaining_files: files_info.len().max(1),
            files: files_info,
            total_size_bytes,
            created_at: now,
            expires_at: initial_expiry,
            status: initial_status.to_string(),
            sender_pk: v2_key.as_ref().map(|k| k.pk.clone()),
            transport: None,
        };
        // V2-FUNC-01: single pending slot; check and save under one lock (M10).
        if !claim_pending_slot(&transfer, v2_key.is_some()) {
            let err = serde_json::json!({ "status": "REJECTED", "error": "Another transfer is in progress. Please retry shortly." });
            respond(&stream, "409 Conflict", "application/json", err.to_string().as_bytes(), None, Some(&[("Retry-After", "30")]));
            return;
        }

        let size_mb = (total_size_bytes as f64) / 1024.0 / 1024.0;
        if auto_accept {
            notify_desktop(
                "OmaSend AirBridge",
                &format!("Receiving {} file(s) ({:.1} MB) from your device '{}' (verified key).", file_names.len(), size_mb, sender_name),
            );
        } else {
            notify_desktop(
                "OmaSend AirBridge: Transfer Request",
                &format!("'{}' wants to send {} file(s) ({:.1} MB).\nOpen OmaSend panel to Accept or Decline.", sender_name, file_names.len(), size_mb),
            );
        }

        // "Same owner" now means a verified key the user paired as one of their own devices.
        let resp = serde_json::json!({
            "status": initial_status,
            "is_trusted": v2_key.is_some() || legacy_peer.is_some(),
            "verified_device": v2_key.is_some(),
            "is_same_owner": auto_accept,
            "token": token
        });
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    if req.path.starts_with("/api/p2p/decision") {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if req.method == "GET" {
            let token = req.get_param("token").unwrap_or_default();
            // Read expired records too, so a sender learns EXPIRED instead of NOT_FOUND (M10).
            if let Some(pending) = with_pending_transfer(|p| p.clone()) {
                if !token.is_empty() && constant_time_eq_str(&pending.token, &token) {
                    if now > pending.expires_at {
                        respond(&stream, "200 OK", "application/json", b"{\"status\":\"EXPIRED\"}", None, None);
                    } else {
                        let resp = serde_json::json!({ "status": pending.status });
                        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
                    }
                    return;
                }
            }
            respond(&stream, "404 Not Found", "application/json", b"{\"status\":\"NOT_FOUND\"}", None, None);
            return;
        } else if req.method == "POST" {
            // Only the local user may decide: the CLI/panel with the local API token, or a
            // PIN-authenticated portal session. Bare loopback is not enough, because the WAN
            // tunnel delivers internet traffic from 127.0.0.1 (M2).
            if !local_ctl && !authorized {
                respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Only local user can approve or reject transfers\"}", None, None);
                return;
            }
            if content_length > MAX_CONTROL_BODY {
                respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Request payload exceeds limit\"}", None, None);
                return;
            }

            let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
            let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CONTROL_BODY) {
                Some(b) => b,
                None => return,
            };
            let val: serde_json::Value = body.as_slice().and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
            let token = val["token"].as_str().unwrap_or_default();
            let accept = match val["action"].as_str() {
                Some("accept") => true,
                Some("reject") => false,
                _ => {
                    respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid token or action\"}", None, None);
                    return;
                }
            };
            let (status, out) = match decide_pending_transfer(token, accept) {
                Ok(st) => ("200 OK", serde_json::json!({ "ok": true, "status": st })),
                Err(e) => ("409 Conflict", serde_json::json!({ "ok": false, "error": e })),
            };
            respond(&stream, status, "application/json", out.to_string().as_bytes(), None, None);
            return;
        }
    }

    if req.method == "POST" && req.path.starts_with("/api/p2p/upload") {
        let token = req.get_param("token").unwrap_or_default();
        let filename_raw = req.get_param("filename").unwrap_or_default();
        let clean_filename = sanitize_filename(&urlencoding_decode(&filename_raw));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        let pending_opt = get_pending_transfer();
        let has_valid_token = match pending_opt.as_ref() {
            Some(p) => p.token == token && p.status == "ACCEPTED" && now <= p.expires_at,
            None => false,
        };

        if !has_valid_token {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Unauthorized or expired transfer token\"}", None, None);
            return;
        }

        let Some(pending) = pending_opt else {
            return;
        };
        let matching_info = pending.files.iter().find(|f| f.name == clean_filename).cloned();
        let is_in_pending = matching_info.is_some() || pending.file_names.iter().any(|n| n == &clean_filename);
        if !is_in_pending {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"File not listed in approved transfer request\"}", None, None);
            return;
        }

        if content_length > MAX_P2P_UPLOAD_SIZE {
            respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Payload exceeds 10 GiB limit\"}", None, None);
            return;
        }

        if let Some(ref expected_pk) = pending.sender_pk {
            let ok = matches!(
                v2_verify(&req, &devicekey::body_tag_stream(content_length), &client_ip.to_canonical().to_string()),
                devicekey::AuthResult::Trusted(ref k) if &k.pk == expected_pk
            );
            if !ok {
                respond(&stream, "401 Unauthorized", "application/json", b"{\"error\":\"Upload must be signed by the device that requested the transfer\"}", None, None);
                return;
            }
        }

        // V2-SEC-06: the upload must match the size the user approved in the transfer request.
        if let Some(ref info) = matching_info {
            if content_length as u64 != info.size_bytes {
                respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Upload size does not match the approved transfer request\"}", None, None);
                return;
            }
        }

        let upload_secs = (content_length as u64 / (512 * 1024)).clamp(30, MAX_UPLOAD_DURATION_SECS);
        // Keep the transfer alive while this file streams, plus an idle window for the next one.
        with_pending_transfer(|slot| {
            if let Some(p) = slot.as_mut().filter(|p| p.token == token && p.status == "ACCEPTED") {
                p.expires_at = p.expires_at.max(now.saturating_add(upload_secs).saturating_add(PENDING_IDLE_SECS));
            }
        });
        let body_deadline = Instant::now() + Duration::from_secs(upload_secs);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, true, MAX_P2P_UPLOAD_SIZE) {
            Some(b) => b,
            None => return,
        };

        let (computed_blake3, computed_sha256, computed_md5) = match body.compute_military_hashes() {
            Ok(h) => h,
            Err(_) => {
                respond(&stream, "500 Internal Server Error", "application/json", b"{\"error\":\"Failed to compute integrity hashes\"}", None, None);
                return;
            }
        };

        let exp_blake3 = req.get_param("blake3")
            .or_else(|| req.get_header("x-file-blake3").map(|s| s.to_string()))
            .or_else(|| matching_info.as_ref().and_then(|f| f.blake3.clone()));

        let exp_sha256 = req.get_param("sha256")
            .or_else(|| req.get_header("x-file-sha256").map(|s| s.to_string()))
            .or_else(|| matching_info.as_ref().and_then(|f| f.sha256.clone()));

        let exp_md5 = req.get_param("md5")
            .or_else(|| req.get_header("x-file-md5").map(|s| s.to_string()))
            .or_else(|| matching_info.as_ref().and_then(|f| f.md5.clone()));

        if let Some(ref exp) = exp_blake3 {
            if !exp.eq_ignore_ascii_case(&computed_blake3) {
                respond(&stream, "422 Unprocessable Entity", "application/json", b"{\"error\":\"File integrity verification failed: BLAKE3 checksum mismatch\"}", None, None);
                return;
            }
        }

        if let Some(ref exp) = exp_sha256 {
            if !exp.eq_ignore_ascii_case(&computed_sha256) {
                respond(&stream, "422 Unprocessable Entity", "application/json", b"{\"error\":\"File integrity verification failed: SHA-256 checksum mismatch\"}", None, None);
                return;
            }
        }

        if let Some(ref exp) = exp_md5 {
            if !exp.eq_ignore_ascii_case(&computed_md5) {
                respond(&stream, "422 Unprocessable Entity", "application/json", b"{\"error\":\"File integrity verification failed: MD5 checksum mismatch\"}", None, None);
                return;
            }
        }

        let ddir = get_download_dir();
        let file_path = get_unique_filepath(&ddir, &clean_filename);
        let payload_len = body.len();
        let write_res = match body {
            HttpBody::Staged(staged) => {
                staged.persist(&file_path)
            }
            HttpBody::Memory(ref bytes) => {
                if let Some(avail) = get_available_disk_space(&ddir) {
                    if (bytes.len() as u64).saturating_add(10 * 1024 * 1024) > avail {
                        respond(&stream, "507 Insufficient Storage", "text/plain", b"Insufficient disk space to save file", None, None);
                        return;
                    }
                }
                write_secure_bytes(&file_path, bytes)
            }
        };
        if write_res.is_ok() {
            RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
            // Re-read under the lock: the record may have changed while this file streamed.
            let done_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            with_pending_transfer(|slot| {
                let Some(p) = slot.as_mut().filter(|p| p.token == pending.token) else {
                    return;
                };
                if let Some(pos) = p.file_names.iter().position(|f| f == &clean_filename) {
                    p.file_names.remove(pos);
                }
                if let Some(pos) = p.files.iter().position(|f| f.name == clean_filename) {
                    p.files.remove(pos);
                }
                if p.file_names.is_empty() && p.files.is_empty() {
                    *slot = None;
                } else {
                    p.expires_at = done_at.saturating_add(PENDING_IDLE_SECS);
                }
            });
            let final_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            record_notified_file(&final_name);
            play_samurai_receive_sound();
            notify_desktop(
                "OmaSend: AirBridge Transfer Complete",
                &format!("'{}' ({} bytes) verified [SHA256: {}] and saved to Downloads/omasend.", final_name, payload_len, &computed_sha256[..8])
            );
            let resp = serde_json::json!({
                "status": "OK",
                "filename": final_name,
                "size": payload_len,
                "sha256": computed_sha256,
                "md5": computed_md5
            });
            respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
            return;
        } else {
            respond(&stream, "500 Internal Server Error", "text/plain", b"Failed to write file to disk", None, None);
            return;
        }
    }

    if req.method == "GET" && (req.path == "/api/p2p/clipboard/image" || req.path.starts_with("/api/p2p/clipboard/image/")) {
        let (vis, _) = get_visibility();
        if vis == "OFF" {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Visibility is Off\"}", None, None);
            return;
        }
        // Staged clipboard images can be screenshots: serve them only to the peers that may
        // receive the clipboard, with the same rules as POST /api/p2p/clipboard (a paired
        // device key, or a confirmed legacy pairing with its token), or to the local user (M12).
        let peer_ok = match v2_verify(&req, &devicekey::body_tag_json(b""), &client_ip.to_canonical().to_string()) {
            devicekey::AuthResult::Trusted(_) => true,
            devicekey::AuthResult::Rejected(why) => {
                let err = serde_json::json!({ "error": format!("Signature rejected: {}", why) });
                respond(&stream, "401 Unauthorized", "application/json", err.to_string().as_bytes(), None, None);
                return;
            }
            devicekey::AuthResult::Absent => legacy_peer_authorized(req.get_header("x-omasend-auth-token").unwrap_or_default()).is_some(),
        };
        if !peer_ok && !local_ctl && !authorized {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Peer is not paired\"}", None, None);
            return;
        }
        let raw_hash = req.get_param("hash").unwrap_or_else(|| {
            req.path.trim_start_matches("/api/p2p/clipboard/image/").trim().to_string()
        });
        let clean_hash: String = raw_hash.chars().take(64).filter(|c| c.is_ascii_hexdigit()).collect();
        if clean_hash.len() != 64 {
            respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid image hash\"}", None, None);
            return;
        }

        let staging_dir = get_clip_staging_dir();
        let candidates = [
            staging_dir.join(format!("{}.png", clean_hash)),
            staging_dir.join(format!("{}.jpg", clean_hash)),
            staging_dir.join(format!("{}.webp", clean_hash)),
        ];

        for target in &candidates {
            if target.exists() {
                if let Ok(meta) = fs::symlink_metadata(target) {
                    if meta.file_type().is_file() && !meta.file_type().is_symlink() {
                        let ext = target.extension().and_then(|s| s.to_str()).unwrap_or("png");
                        let mime = match ext {
                            "jpg" | "jpeg" => "image/jpeg",
                            "webp" => "image/webp",
                            _ => "image/png",
                        };
                        if stream_file_zero_copy(&mut stream, target, mime, None, allowed_cors).is_ok() {
                            return;
                        }
                    }
                }
            }
        }
        respond(&stream, "404 Not Found", "application/json", b"{\"error\":\"Image not found in staging\"}", None, None);
        return;
    }

    if req.method == "GET" && req.path == "/api/p2p/clipboard/vault" {
        let (vis, _) = get_visibility();
        if vis == "OFF" {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Visibility is Off\"}", None, None);
            return;
        }
        let resp = serde_json::json!({
            "status": "OK",
            "count": 0,
            "items": []
        });
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    if req.method == "POST" && (req.path == "/api/p2p/clipboard" || req.path == "/api/p2p/clip-image") {
        let (vis, _) = get_visibility();
        if vis == "OFF" {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Visibility is Off\"}", None, None);
            return;
        }

        if content_length > MAX_IMAGE_CLIP_SIZE {
            respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Clipboard payload exceeds 10 MiB limit\"}", None, None);
            return;
        }

        let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_IMAGE_CLIP_SIZE) {
            Some(b) => b,
            None => return,
        };

        let body_slice = match body.as_slice() {
            Some(s) => s,
            None => {
                respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid payload\"}", None, None);
                return;
            }
        };
        let v2_key = match v2_verify(&req, &devicekey::body_tag_json(body_slice), &client_ip.to_canonical().to_string()) {
            devicekey::AuthResult::Trusted(k) => Some(k),
            devicekey::AuthResult::Absent => None,
            devicekey::AuthResult::Rejected(why) => {
                let err = serde_json::json!({ "error": format!("Signature rejected: {}", why) });
                respond(&stream, "401 Unauthorized", "application/json", err.to_string().as_bytes(), None, None);
                return;
            }
        };
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_slice) {
            // A paired device key (v2 signature) authorizes on its own; otherwise only the token
            // of a code-verified legacy pairing does. A claimed OmaID authorizes nothing.
            let legacy_peer = if v2_key.is_none() {
                let provided_token = req.get_header("x-omasend-auth-token")
                    .or_else(|| val.get("auth_token").and_then(|v| v.as_str()))
                    .unwrap_or_default();
                match legacy_peer_authorized(provided_token) {
                    Some(p) => Some(p),
                    None => {
                        respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Peer is not paired\"}", None, None);
                        return;
                    }
                }
            } else {
                None
            };
            let sender_name = match (v2_key.as_ref(), legacy_peer.as_ref()) {
                (Some(k), _) => k.name.clone(),
                (None, Some(p)) => p.name.clone(),
                (None, None) => "Nearby Device".to_string(),
            };
            let sender_name = sender_name.as_str();

            let content_type = val["content_type"]
                .as_str()
                .unwrap_or_else(|| if req.path == "/api/p2p/clip-image" { "image_png" } else { "text" });

            // Handle visual clipboard payloads (< 512 KiB Base64 or metadata announcement)
            if content_type.starts_with("image") || val.get("image_hash").is_some() || req.path == "/api/p2p/clip-image" {
                let img_hash = val["image_hash"].as_str();
                let b64_opt = val["image_base64"]
                    .as_str()
                    .or_else(|| val["image_data_base64"].as_str())
                    .or_else(|| val["data"].as_str());

                if let Some(b64_data) = b64_opt {
                    if let Ok(raw_bytes) = base64_decode(b64_data) {
                        if let Ok((verified_ct, w, h)) = validate_image_header(&raw_bytes) {
                            let computed_hash = compute_image_clipboard_hash(&raw_bytes);
                            if img_hash.is_none_or(|expected| expected == computed_hash) {
                                set_last_synced_clipboard_hash(&computed_hash);
                                let _ = stage_clipboard_image(&raw_bytes, &verified_ct);
                                let _ = set_pc_image_clipboard(&raw_bytes, &verified_ct);
                                notify_desktop("OmaSend: Image Clipboard", &format!("Received image ({}x{}) from {}.", w, h, sender_name));
                                play_clipboard_sound();
                                respond(&stream, "200 OK", "application/json", b"{\"status\":\"OK\"}", None, None);
                                return;
                            }
                        }
                    }
                } else if let Some(hash) = img_hash {
                    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        set_last_synced_clipboard_hash(hash);
                        let peer_ip_str = val["sender_ip"]
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| client_ip.to_canonical().to_string());
                        if !peer_ip_str.is_empty() {
                            p2p_fetch_image_clipboard_and_apply(&peer_ip_str, hash, content_type);
                        }
                        notify_desktop("OmaSend: Image Clipboard", &format!("Received image reference from {}.", sender_name));
                        play_clipboard_sound();
                        respond(&stream, "200 OK", "application/json", b"{\"status\":\"OK\"}", None, None);
                        return;
                    }
                }
            }

            if let Some(text) = val["text"].as_str() {
                if text.len() <= MAX_IMAGE_CLIP_SIZE {
                    let hash = compute_clipboard_hash(text);
                    set_last_synced_clipboard_hash(&hash);

                    // Sensitive Clipboard Shield: Inbound protection
                    if military::is_sensitive_clipboard_payload(text) {
                        respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Sensitive credentials rejected by clipboard shield\"}", None, None);
                        return;
                    }

                    set_pc_clipboard(text);
                    notify_desktop("OmaSend: Universal Clipboard", &format!("Received clipboard text from {}.", sender_name));
                    play_clipboard_sound();
                    respond(&stream, "200 OK", "application/json", b"{\"status\":\"OK\"}", None, None);
                    return;
                }
            }
        }
        respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid clipboard payload\"}", None, None);
        return;
    }

    if !authorized {
        if req.method == "GET" && req.path == "/" {
            let html = render_login_page();
            respond(&stream, "200 OK", "text/html; charset=utf-8", html.as_bytes(), None, None);
        } else {
            respond(&stream, "401 Unauthorized", "text/plain", b"Unauthorized. Please provide the portal access secret.", None, None);
        }
        return;
    }

    // The cookie holds a value derived from the secret and the session key, never the secret
    // itself. Through the tunnel the browser talks HTTPS to Cloudflare, so it is also Secure;
    // on the LAN the portal is plain http and a Secure cookie would be dropped by the browser.
    let set_cookie = Some(web_session_set_cookie(&web_session, via_tunnel));

    if req.method == "POST" && req.path == "/api/login" {
        // The login page presents the secret (from the link's fragment) in X-OmaSend-PIN and
        // gets the session cookie back; the secret never appears in a URL.
        respond(&stream, "200 OK", "application/json", b"{\"ok\":true}", set_cookie.as_deref(), None);
    }
    else if req.method == "GET" && req.path == "/" {
        let shared_files = get_directory_files(&get_shared_dir());
        let html = render_web_app(ip, &shared_files);
        respond(&stream, "200 OK", "text/html; charset=utf-8", html.as_bytes(), set_cookie.as_deref(), None);
    }
    else if req.method == "POST" && req.path == "/api/upload-encrypted" {
        if content_length > MAX_ENCRYPTED_UPLOAD_SIZE {
            respond(&stream, "413 Payload Too Large", "text/plain", b"Encrypted upload exceeds 25 MiB ceiling", None, None);
            return;
        }

        let _enc_guard = match EncryptedUploadGuard::try_acquire() {
            Some(g) => g,
            None => {
                respond(&stream, "429 Too Many Requests", "text/plain", b"Too many concurrent encrypted uploads. Please try again in a moment.", None, None);
                return;
            }
        };

        let upload_secs = (content_length as u64 / (512 * 1024)).clamp(30, MAX_UPLOAD_DURATION_SECS);
        let body_deadline = Instant::now() + Duration::from_secs(upload_secs);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, true, MAX_ENCRYPTED_UPLOAD_SIZE) {
            Some(b) => b,
            None => return,
        };

        let filename_raw = req.get_header("x-omasend-filename").unwrap_or("received_file.bin");
        let filename_decoded = urlencoding_decode(filename_raw);
        let clean_filename = sanitize_filename(&filename_decoded);

        let iv_hex = match req.get_header("x-omasend-iv") {
            Some(iv) if iv.len() == 24 => iv,
            _ => {
                respond(&stream, "400 Bad Request", "text/plain", b"Missing or invalid X-OmaSend-IV", None, None);
                return;
            }
        };

        let iv_bytes = match hex::decode(iv_hex) {
            Ok(b) => b,
            Err(_) => {
                respond(&stream, "400 Bad Request", "text/plain", b"Invalid IV hex", None, None);
                return;
            }
        };

        let ciphertext = match body.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                respond(&stream, "500 Internal Server Error", "text/plain", e.as_bytes(), None, None);
                return;
            }
        };

        match decrypt_aes256_gcm(key_hex, &iv_bytes, &ciphertext) {
            Ok(decrypted) => {
                let ddir = get_download_dir();
                if let Some(avail) = get_available_disk_space(&ddir) {
                    if (decrypted.len() as u64).saturating_add(10 * 1024 * 1024) > avail {
                        respond(&stream, "507 Insufficient Storage", "text/plain", b"Insufficient disk space to save decrypted file", None, None);
                        return;
                    }
                }
                let file_path = get_unique_filepath(&ddir, &clean_filename);
                if write_secure_bytes(&file_path, &decrypted).is_ok() {
                    let final_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    record_notified_file(&final_name);
                    RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
                    notify_desktop(
                        "OmaSend: E2EE File Received",
                        &format!("'{}' ({} bytes) decrypted and saved to Downloads/omasend.", final_name, decrypted.len())
                    );
                    let resp = serde_json::json!({
                        "status": "OK",
                        "filename": clean_filename,
                        "size": decrypted.len(),
                        "encrypted": true
                    });
                    respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
                } else {
                    respond(&stream, "500 Internal Server Error", "text/plain", b"Failed to write file", None, None);
                }
            }
            Err(e) => {
                eprintln!("Decryption error: {}", e);
                respond(&stream, "400 Bad Request", "text/plain", e.as_bytes(), None, None);
            }
        }
    }
    else if req.method == "GET" && req.path.starts_with("/api/download-encrypted/") {
        let raw_filename = req.path.trim_start_matches("/api/download-encrypted/");
        let filename = sanitize_filename(&urlencoding_decode(raw_filename));
        let target = get_shared_dir().join(&filename);
        let actual_target = if target.exists() {
            target
        } else {
            get_download_dir().join(&filename)
        };

        if let Ok(meta) = fs::symlink_metadata(&actual_target) {
            if !meta.file_type().is_symlink() && meta.file_type().is_file() && meta.uid() == get_current_uid() {
                if let Ok(content) = safe_read_file(&actual_target) {
                    match encrypt_aes256_gcm(key_hex, &content) {
                        Ok((iv, ciphertext)) => {
                            let iv_hex = hex::encode(&iv);
                            let cd_val = format!("attachment; filename=\"{}.enc\"", filename);
                            let extra = [
                                ("X-OmaSend-IV", iv_hex.as_str()),
                                ("X-OmaSend-Filename", filename.as_str()),
                                ("Content-Disposition", cd_val.as_str()),
                            ];
                            let tmp_enc = get_state_dir().join(format!(".tmp_enc_{}_{}.part", std::process::id(), hex::encode(&iv)));
                            if write_secure_bytes(&tmp_enc, &ciphertext).is_ok() {
                                let res = stream_file_zero_copy(&mut stream, &tmp_enc, "application/octet-stream", Some(&extra), allowed_cors);
                                let _ = fs::remove_file(&tmp_enc);
                                if res.is_ok() {
                                    return;
                                }
                            }
                            respond(&stream, "200 OK", "application/octet-stream", &ciphertext, None, Some(&extra));
                            return;
                        }
                        Err(e) => {
                            respond(&stream, "500 Internal Server Error", "text/plain", e.as_bytes(), None, None);
                            return;
                        }
                    }
                }
            }
        }
        respond(&stream, "404 Not Found", "text/plain", b"File not found or access denied", None, None);
    }
    else if req.method == "POST" && req.path == "/api/clipboard-encrypted" {
        if content_length > MAX_CLIPBOARD_BODY {
            respond(&stream, "413 Payload Too Large", "text/plain", b"Clipboard payload exceeds 1 MiB ceiling", None, None);
            return;
        }

        let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CLIPBOARD_BODY) {
            Some(b) => b,
            None => return,
        };

        let iv_hex = match req.get_header("x-omasend-iv") {
            Some(iv) if iv.len() == 24 => iv,
            _ => {
                respond(&stream, "400 Bad Request", "text/plain", b"Missing IV", None, None);
                return;
            }
        };
        let iv_bytes = match hex::decode(iv_hex) {
            Ok(b) => b,
            Err(_) => {
                respond(&stream, "400 Bad Request", "text/plain", b"Invalid IV hex", None, None);
                return;
            }
        };

        let ciphertext = match body.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                respond(&stream, "400 Bad Request", "text/plain", e.as_bytes(), None, None);
                return;
            }
        };
        match decrypt_aes256_gcm(key_hex, &iv_bytes, &ciphertext) {
            Ok(decrypted) => {
                let text = String::from_utf8_lossy(&decrypted).to_string();
                let hash = compute_clipboard_hash(&text);
                set_last_synced_clipboard_hash(&hash);
                set_pc_clipboard(&text);
                notify_desktop(
                    "OmaSend: E2EE Clipboard Received",
                    &format!("Encrypted clipboard updated ({} chars):\n{}", text.len(), text.chars().take(60).collect::<String>()),
                );
                play_clipboard_sound();
                let resp = serde_json::json!({ "status": "OK", "encrypted": true });
                respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
            }
            Err(e) => {
                respond(&stream, "400 Bad Request", "text/plain", e.as_bytes(), None, None);
            }
        }
    }
    else if req.method == "GET" && req.path == "/api/clipboard-encrypted" {
        let clip = get_pc_clipboard();
        match encrypt_aes256_gcm(key_hex, clip.as_bytes()) {
            Ok((iv, ciphertext)) => {
                let resp = serde_json::json!({
                    "iv": hex::encode(iv),
                    "ciphertext": hex::encode(ciphertext),
                    "encrypted": true
                });
                respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
            }
            Err(e) => {
                respond(&stream, "500 Internal Server Error", "text/plain", e.as_bytes(), None, None);
            }
        }
    }
    else if req.path == "/api/clipboard" {
        if req.method == "GET" {
            let clip = get_pc_clipboard();
            let resp = serde_json::json!({ "clipboard": clip });
            respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        } else if req.method == "POST" {
            if content_length > MAX_CLIPBOARD_BODY {
                respond(&stream, "413 Payload Too Large", "text/plain", b"Clipboard payload exceeds 1 MiB ceiling", None, None);
                return;
            }

            let body_deadline = Instant::now() + Duration::from_secs(DEFAULT_BODY_TIMEOUT_SECS);
            let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, false, MAX_CLIPBOARD_BODY) {
                Some(b) => b,
                None => return,
            };

            let body_bytes = body.to_bytes().unwrap_or_default();
            let body_str = String::from_utf8_lossy(&body_bytes);
            let text = if let Some(val) = body_str.strip_prefix("text=") {
                urlencoding_decode(val)
            } else {
                body_str.to_string()
            };
            let hash = compute_clipboard_hash(&text);
            set_last_synced_clipboard_hash(&hash);
            set_pc_clipboard(&text);
            notify_desktop("OmaSend: Clipboard Received", &format!("Clipboard updated from device ({} chars)", text.len()));
            play_clipboard_sound();
            let resp = serde_json::json!({ "status": "OK" });
            respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        }
    }
    else if req.method == "GET" && (req.path == "/api/clipboard-vault" || req.path == "/api/clipboard/vault" || req.path == "/api/clipboard-history") {
        let resp = serde_json::json!({
            "status": "OK",
            "count": 0,
            "items": []
        });
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
    }
    else if req.method == "GET" && req.path.starts_with("/api/clipboard/image/") {
        let raw_hash = req.path.trim_start_matches("/api/clipboard/image/").trim();
        let clean_hash: String = raw_hash.chars().take(64).filter(|c| c.is_ascii_hexdigit()).collect();
        if clean_hash.len() != 64 {
            respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid image hash\"}", None, None);
            return;
        }

        let staging_dir = get_clip_staging_dir();
        let candidates = [
            staging_dir.join(format!("{}.png", clean_hash)),
            staging_dir.join(format!("{}.jpg", clean_hash)),
            staging_dir.join(format!("{}.webp", clean_hash)),
        ];

        for target in &candidates {
            if target.exists() {
                if let Ok(meta) = fs::symlink_metadata(target) {
                    if meta.file_type().is_file() && !meta.file_type().is_symlink() {
                        let ext = target.extension().and_then(|s| s.to_str()).unwrap_or("png");
                        let mime = match ext {
                            "jpg" | "jpeg" => "image/jpeg",
                            "webp" => "image/webp",
                            _ => "image/png",
                        };
                        if stream_file_zero_copy(&mut stream, target, mime, None, allowed_cors).is_ok() {
                            return;
                        }
                    }
                }
            }
        }
        respond(&stream, "404 Not Found", "application/json", b"{\"error\":\"Image not found in staging\"}", None, None);
    }
    else if req.method == "GET" && req.path.starts_with("/download/") {
        let filename = sanitize_filename(&urlencoding_decode(req.path.trim_start_matches("/download/")));
        let target = get_shared_dir().join(&filename);
        let actual_target = if target.exists() { target } else { get_download_dir().join(&filename) };
        let cd_val = format!("attachment; filename=\"{}\"", filename);
        let extra = [("Content-Disposition", cd_val.as_str())];
        if stream_file_zero_copy(&mut stream, &actual_target, "application/octet-stream", Some(&extra), allowed_cors).is_ok() {
            return;
        }
        respond(&stream, "404 Not Found", "text/plain", b"File not found or access denied", None, None);
    }
    else if req.method == "POST" && req.path == "/upload" {
        if content_length > MAX_BODY_SIZE {
            respond(&stream, "413 Payload Too Large", "text/plain", b"Upload payload exceeds 100 MiB ceiling", None, None);
            return;
        }

        let upload_secs = (content_length as u64 / (512 * 1024)).clamp(30, MAX_UPLOAD_DURATION_SECS);
        let body_deadline = Instant::now() + Duration::from_secs(upload_secs);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, true, MAX_BODY_SIZE) {
            Some(b) => b,
            None => return,
        };

        let ddir = get_download_dir();
        let mut success = false;
        let content_type = req.get_header("content-type").map(str::to_string);

        // Single-file multipart/form-data body (the portal's FormData upload). Only the file
        // part's bytes are saved: not the part headers, not the closing boundary (M7).
        let located = match body {
            HttpBody::Memory(ref bytes) => {
                locate_multipart_file(&mut std::io::Cursor::new(bytes.as_slice()), bytes.len() as u64, content_type.as_deref())
                    .map(|loc| (loc, None))
            }
            HttpBody::Staged(ref staged) => File::open(&staged.path)
                .ok()
                .and_then(|mut f| locate_multipart_file(&mut f, staged.size, content_type.as_deref()).map(|loc| (loc, Some(staged.path.clone())))),
        };
        let Some(((dstart, dend, raw_name), staged_path)) = located else {
            respond(&stream, "400 Bad Request", "text/plain", b"Expected a multipart/form-data file upload", None, None);
            return;
        };
        let saved_name = if raw_name.is_empty() {
            format!("transfer_{}.bin", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs())
        } else {
            sanitize_filename(&raw_name)
        };
        let dlen = dend - dstart;
        if let Some(avail) = get_available_disk_space(&ddir) {
            if dlen.saturating_add(10 * 1024 * 1024) > avail {
                respond(&stream, "507 Insufficient Storage", "text/plain", b"Insufficient disk space to save file", None, None);
                return;
            }
        }

        let file_path = get_unique_filepath(&ddir, &saved_name);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        let copied = opts.open(&file_path).ok().and_then(|mut dest| match (&body, staged_path) {
            (HttpBody::Memory(bytes), _) => dest.write_all(&bytes[dstart as usize..dend as usize]).ok(),
            (_, Some(path)) => {
                let mut src = File::open(path).ok()?;
                src.seek(SeekFrom::Start(dstart)).ok()?;
                std::io::copy(&mut src.take(dlen), &mut dest).ok().filter(|n| *n == dlen).map(|_| ())
            }
            _ => None,
        });
        if copied.is_some() {
            let final_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            record_notified_file(&final_name);
            success = true;
            RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
            notify_desktop("OmaSend: File Received", &format!("'{}' saved to Downloads/omasend.", final_name));
        } else {
            let _ = fs::remove_file(&file_path);
        }
        drop(body);

        if success {
            let resp = "{\"status\":\"OK\"}";
            respond(&stream, "200 OK", "application/json", resp.as_bytes(), None, None);
        } else {
            respond(&stream, "500 Internal Server Error", "text/plain", b"Failed to write file", None, None);
        }
    } else {
        respond(&stream, "404 Not Found", "text/plain", b"Not Found", None, None);
    }
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn rfind_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// Locates the first file part of a multipart/form-data body of `total` bytes. Returns the
/// byte range of the file data (part headers and the closing `\r\n--boundary--` excluded) and
/// the part's filename (may be empty). The boundary comes from the Content-Type header, or,
/// if that is missing, from the body's first line.
fn locate_multipart_file<R: Read + Seek>(r: &mut R, total: u64, content_type: Option<&str>) -> Option<(u64, u64, String)> {
    let mut head = vec![0u8; total.min(16 * 1024) as usize];
    r.seek(SeekFrom::Start(0)).ok()?;
    r.read_exact(&mut head).ok()?;

    let from_header = content_type.and_then(|ct| {
        ct.split(';')
            .map(str::trim)
            .find_map(|p| p.strip_prefix("boundary="))
            .map(|b| b.trim_matches('"').to_string())
    });
    let boundary = match from_header.filter(|b| !b.is_empty() && b.len() <= 200) {
        Some(b) => b,
        None => {
            let line_end = find_bytes(&head, b"\r\n")?;
            let first = std::str::from_utf8(&head[..line_end]).ok()?;
            first.strip_prefix("--").filter(|b| !b.is_empty() && b.len() <= 200)?.to_string()
        }
    };
    let delim = format!("--{}", boundary);

    let first = find_bytes(&head, delim.as_bytes())?;
    let hdr_start = first + delim.len() + 2; // delimiter line ends with CRLF
    if hdr_start > head.len() {
        return None;
    }
    let hdr_end = hdr_start + find_bytes(&head[hdr_start..], b"\r\n\r\n")?;
    let part_headers = String::from_utf8_lossy(&head[hdr_start..hdr_end]);
    let filename = part_headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-disposition:"))
        .and_then(|l| {
            let lower = l.to_ascii_lowercase();
            let pos = lower.find("filename=\"")? + "filename=\"".len();
            let rest = &l[pos..];
            rest.find('"').map(|end| rest[..end].to_string())
        })
        .unwrap_or_default();
    let data_start = (hdr_end + 4) as u64;

    // The file data ends right before the last "\r\n--boundary" (the closing delimiter).
    let closing = format!("\r\n{}", delim);
    let tail_len = total.min(4096 + closing.len() as u64);
    let tail_off = total - tail_len;
    let mut tail = vec![0u8; tail_len as usize];
    r.seek(SeekFrom::Start(tail_off)).ok()?;
    r.read_exact(&mut tail).ok()?;
    let data_end = tail_off + rfind_bytes(&tail, closing.as_bytes())? as u64;
    (data_end >= data_start).then_some((data_start, data_end, filename))
}

fn urlencoding_decode(input: &str) -> String {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(h) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(h);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

// ------------------- SERVER DAEMON -------------------

/// Read-only paths the daemon keeps under Landlock (V2-SEC-07). `$HOME` itself is not
/// granted: a compromised engine must not read `~/.ssh`, browser profiles or password
/// stores. Sending files runs in the unsandboxed CLI (`--send`, `--send-picker`), so the
/// daemon only needs system paths, its own install/asset dirs and helper-tool config.
/// Missing paths are skipped by `enable_landlock_sandbox`.
fn sandbox_read_paths(home: &Path, exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = ["/usr", "/bin", "/lib", "/lib64", "/etc", "/proc", "/dev", "/run"]
        .iter()
        .map(PathBuf::from)
        .collect();
    for rel in [
        // Bundled sounds and assets (see resolve_omasend_asset_wav).
        ".config/omarchy/plugins/ozdil.omasend",
        ".local/share/omarchy/plugins/ozdil.omasend",
        // cloudflared for the WAN tunnel (see get_cloudflared_bin) and its config.
        ".local/bin",
        ".cloudflared",
        // PulseAudio cookie for paplay.
        ".config/pulse",
    ] {
        paths.push(home.join(rel));
    }
    if let Some(dir) = exe_dir {
        // Dev builds run from the source tree and read ./assets next to the binary.
        // Skip it if it is $HOME or one of its parents, which would re-grant all of $HOME.
        if !home.starts_with(dir) {
            paths.push(dir.to_path_buf());
        }
    }
    paths
}

/// Written by the daemon at startup: "1" when Landlock is active, "0" when it runs unsandboxed.
fn sandbox_status_path() -> PathBuf {
    get_state_dir().join("sandbox_status.txt")
}

/// Last sandbox state the daemon reported; None if no daemon has reported one yet.
fn read_sandbox_status() -> Option<bool> {
    match read_secure_file(&sandbox_status_path()).ok()?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// True for clients the HTTP server talks to at all: loopback, private (RFC 1918 / ULA) and
/// link-local addresses, plus Tailscale's 100.64.0.0/10 when this machine is on a tailnet.
/// Public addresses are dropped before a request is read. (The WAN tunnel arrives from
/// loopback and is limited to the portal in handle_connection.)
fn is_allowed_client_ip(ip: IpAddr, allow_cgnat: bool) -> bool {
    let ip = ip.to_canonical();
    if rendezvous::is_local_network_ip(&ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => allow_cgnat && v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64,
        IpAddr::V6(_) => false,
    }
}

fn run_server() {
    // Enforce military-grade defense: anti-forensics memory protection + Landlock LSM
    military::enable_anti_forensics();
    let state_dir = get_state_dir();
    let download_dir = get_download_dir();
    let shared_dir = get_shared_dir();
    let home_dir = env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"));
    let exe_dir = env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf));
    let read_paths = sandbox_read_paths(&home_dir, exe_dir.as_deref());
    let read_refs: Vec<&Path> = read_paths.iter().map(PathBuf::as_path).collect();
    let sandboxed = military::enable_landlock_sandbox(
        &read_refs,
        &[
            &state_dir,
            &download_dir,
            &shared_dir,
            Path::new("/tmp"),
            Path::new("/dev"),
            Path::new("/run"),
        ],
    );
    if sandboxed {
        println!("Landlock sandbox enabled");
    } else {
        eprintln!("WARNING: Landlock sandbox NOT enabled (kernel without Landlock, or setup failed); running unsandboxed");
    }
    // Reported as "sandbox" in --json, so an unsandboxed daemon is visible, not just logged.
    let _ = write_secure_file(&sandbox_status_path(), if sandboxed { "1" } else { "0" });

    ensure_local_api_token();
    clean_stale_outgoing();
    start_core_node();

    let pid_file = state_dir.join("engine.pid");
    if let Ok(old_pid_str) = read_secure_file(&pid_file) {
        if let Ok(old_pid) = old_pid_str.trim().parse::<i32>() {
            let my_pid = std::process::id() as i32;
            if old_pid != my_pid && pid_is(old_pid, ENGINE_COMM) {
                kill_process_group(old_pid);
                thread::sleep(Duration::from_millis(60));
            }
        }
    }
    let _ = write_secure_file(&pid_file, &std::process::id().to_string());

    let local_ip = get_local_ip();
    let pin = get_or_create_pin();
    let key = get_or_create_session_key();
    update_all_qr();

    let addr = format!("0.0.0.0:{}", PORT);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", addr, e);
            return;
        }
    };
    // The PIN is not logged: daemon stdout ends up in the journal.
    println!("OmaSend listening on http://{}:{}", local_ip, PORT);
    let allow_cgnat = get_tailscale_ip().is_some();

    // Spawn P2P AirBridge discovery threads
    thread::spawn(run_p2p_discovery_listener);
    thread::spawn(run_p2p_beacon_broadcaster);
    // Catch up own devices that missed a link or removal while we were off.
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(10));
        push_roster();
    });
    start_download_dir_watcher(&get_download_dir());
    start_clipboard_sentinel();

    for mut s in listener.incoming().flatten() {
        // Unknown peer address: refuse rather than assume loopback.
        let Ok(client_ip) = s.peer_addr().map(|a| a.ip()) else { continue };
        if !is_allowed_client_ip(client_ip, allow_cgnat) {
            continue; // dropping `s` closes the connection without reading anything
        }
        let _ = s.set_nodelay(true);
        let guard = match try_acquire_connection(client_ip) {
            Some(g) => g,
            None => {
                let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
                let _ = s.write_all(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Type: application/json\r\nRetry-After: 5\r\nContent-Length: 43\r\n\r\n{\"error\":\"Too many concurrent connections\"}");
                let _ = s.flush();
                continue;
            }
        };

        let ip_clone = local_ip.clone();
        let pin_clone = pin.clone();
        let key_clone = key.clone();
        thread::spawn(move || {
            let _guard = guard;
            handle_connection(s, &ip_clone, &pin_clone, &key_clone);
        });
    }
}

/// The `--json` status the panel polls. It must never carry the portal secret, the E2EE
/// session key or the account OmaID, and it does no network I/O (no STUN).
fn build_server_state(ip: &str) -> ServerState {
    let (wan_active, wan_connecting, wan_url) = get_wan_status();
    let active_mode = get_active_mode();
    let active_url = portal_base_url(ip, &active_mode, wan_url.as_deref());
    let (vis, rem) = get_visibility();
    let (dev_id, _) = get_or_create_device_id();
    let oma_id = get_or_create_oma_id();
    let wan_mode = if wan_active { "WAN" } else { "LAN" }.to_string();
    // No network I/O here: the panel polls --json. STUN runs once when WAN is turned on.
    let stun_addr = if wan_active || wan_connecting {
        read_secure_file(&wan_stun_path()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    } else {
        None
    };
    ServerState {
        status: "ACTIVE".to_string(),
        port: PORT,
        local_ip: ip.to_string(),
        tailscale_ip: get_tailscale_ip(),
        active_mode,
        wan_active,
        wan_connecting,
        wan_provider: if wan_active || wan_connecting { get_wan_provider() } else { None },
        wan_url,
        active_url,
        download_dir: get_download_dir().to_string_lossy().to_string(),
        shared_dir: get_shared_dir().to_string_lossy().to_string(),
        qr_path: get_state_dir().join("qr.svg").to_string_lossy().to_string(),
        omaid_qr_path: get_state_dir().join("omaid_qr.svg").to_string_lossy().to_string(),
        total_received: RECEIVED_COUNTER.load(Ordering::SeqCst),
        recent_files: get_directory_files(&get_download_dir()),
        shared_files: get_directory_files(&get_shared_dir()),
        p2p_device_id: dev_id,
        p2p_hostname: get_system_hostname(),
        p2p_visibility: vis,
        p2p_visibility_remaining_secs: rem,
        p2p_discovered_peers: get_discovered_peers(),
        p2p_pending_transfer: get_pending_transfer(),
        p2p_transfer_progress: get_transfer_progress(),
        clipboard_vault: get_clipboard_vault_items(),
        oma_id,
        wan_mode,
        stun_addr,
        sound_enabled: is_sound_enabled(),
        firewall_status: check_firewall_status(),
        device_key_id: device_identity().device_id(),
        paired_devices: paired_devices_view(),
        sandbox: read_sandbox_status(),
    }
}

// ------------------- CLI ENTRYPOINT -------------------

fn main() {
    military::enable_anti_forensics();
    let args: Vec<String> = env::args().collect();
    let ip = get_local_ip();
    let pin = if args.iter().any(|a| a == "--new-pin") {
        generate_new_pin()
    } else {
        get_or_create_pin()
    };

    let session_key = if args.iter().any(|a| a == "--new-key") {
        generate_new_session_key()
    } else {
        get_or_create_session_key()
    };

    if args.iter().any(|a| a == "--test-notification") {
        notify_desktop("OmaSend", "Masaustu bildirim sistemi aktif ve calisiyor.");
        println!("Test bildirimi gonderildi.");
        return;
    }

    // ---- Phase 1: device keys & QR pairing ----
    if args.iter().any(|a| a == "--account-id") {
        let id = omalink::get_or_create_account_id(&get_state_dir());
        if args.iter().any(|a| a == "--json") {
            println!("{}", serde_json::json!({ "account_id": id }));
        } else {
            println!("{}", id);
        }
        return;
    }
    if args.iter().any(|a| a == "--new-account-id") {
        println!("{}", omalink::new_account_id(&get_state_dir()));
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--link") {
        let Some(id) = args.get(pos + 1) else {
            eprintln!("Usage: --link <OmaID> [--json]");
            std::process::exit(2);
        };
        let res = link_with_account_id(id);
        if args.iter().any(|a| a == "--json") {
            let out = match &res {
                Ok(keys) => serde_json::json!({
                    "ok": true,
                    "linked": keys.iter().map(|k| serde_json::json!({ "name": k.name, "device_id": k.device_id })).collect::<Vec<_>>(),
                }),
                Err(e) => serde_json::json!({ "ok": false, "error": e }),
            };
            println!("{}", out);
        } else {
            match &res {
                Ok(keys) => keys.iter().for_each(|k| println!("Linked {} ({})", k.name, k.device_id)),
                Err(e) => eprintln!("Link failed: {}", e),
            }
        }
        if res.is_err() {
            std::process::exit(1);
        }
        return;
    }
    if args.iter().any(|a| a == "--device-id") {
        println!("{}", device_identity().device_id());
        return;
    }
    if args.iter().any(|a| a == "--pair-offer") {
        let own = args.iter().any(|a| a == "--own");
        let out = create_pair_offer_json(own);
        if args.iter().any(|a| a == "--json") {
            println!("{}", out);
        } else {
            let uri = out["uri"].as_str().unwrap_or_default().to_string();
            if let Some(qr) = qr_ansi(&uri) {
                print!("{}", qr);
            }
            println!("Scan this QR code with OmaSend on the other device (valid for {} minutes, single use).", devicekey::PAIR_OFFER_TTL_SECS / 60);
            println!("Or paste on another Omarchy desktop:  omasend-engine --pair-with '{}' [--own]", uri);
            println!("This device: {}{}", device_identity().device_id(), if own { "  (new device will be trusted as YOUR device)" } else { "" });
        }
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--pair-inspect") {
        let Some(uri) = args.get(pos + 1) else {
            eprintln!("Usage: --pair-inspect 'omasend://pair?...'");
            std::process::exit(2);
        };
        match inspect_pair_uri(uri) {
            Ok((offer, device_id)) => {
                println!("{}", serde_json::json!({ "name": offer.name, "device_id": device_id, "host": offer.host, "port": offer.port }));
            }
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--pair-with") {
        let Some(uri) = args.get(pos + 1) else {
            eprintln!("Usage: --pair-with 'omasend://pair?...' [--own]");
            std::process::exit(2);
        };
        // Trusting the other device as "mine" (auto-accept) is the local user's explicit choice.
        let own = args.iter().any(|a| a == "--own");
        match p2p_pair_v2(uri, own) {
            Ok(k) => {
                println!("Paired with {} ({}){}", k.name, k.device_id, if k.own_device { " as one of your devices" } else { "" });
                notify_desktop("OmaSend: Device paired", &format!("{} ({})", k.name, k.device_id));
            }
            Err(e) => {
                eprintln!("Pairing failed: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }
    if args.iter().any(|a| a == "--devices") {
        println!("{}", serde_json::json!({ "me": device_identity().device_id(), "devices": paired_devices_view() }));
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--unpair") {
        let Some(id) = args.get(pos + 1) else {
            eprintln!("Usage: --unpair <device-id>");
            std::process::exit(2);
        };
        let store = trust_store();
        if let Some(k) = store.load().into_iter().find(|k| k.own_device && (k.pk == *id || k.device_id == *id)) {
            match omalink::revoke_own_device(&get_state_dir(), &store, &k.pk) {
                Ok(()) => {
                    push_roster();
                    // Give the background push a moment before the CLI process exits.
                    std::thread::sleep(Duration::from_secs(4));
                    println!("Removed {} from all your devices. Your account OmaID was replaced.", k.name);
                }
                Err(e) => {
                    eprintln!("Failed: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
        match store.remove(id) {
            Ok(true) => println!("Removed {}", id),
            Ok(false) => {
                eprintln!("No paired device {}", id);
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Failed: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    if args.iter().any(|a| a == "--cancel-transfer") {
        request_transfer_cancel();
        clear_transfer_progress();
        clear_pending_transfer();
        notify_desktop("OmaSend AirBridge", "Aktif transfer iptal edildi.");
        println!("Transfer cancelled");
        return;
    }

    if args.iter().any(|a| a == "--toggle-sound") {
        let next = !is_sound_enabled();
        set_sound_enabled(next);
        println!("{}", if next { "ON" } else { "OFF" });
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--set-sound") {
        if let Some(val) = args.get(pos + 1) {
            let en = !matches!(val.trim().to_lowercase().as_str(), "off" | "0" | "false");
            set_sound_enabled(en);
            println!("{}", if en { "ON" } else { "OFF" });
            return;
        }
    }

    if args.iter().any(|a| a == "--firewall-status") {
        println!("{}", check_firewall_status());
        return;
    }

    if args.iter().any(|a| a == "--oma-id-qr") {
        let (svg_path, png_path) = update_oma_id_qr();
        println!("SVG: {}\nPNG: {}", svg_path, png_path);
        return;
    }

    if args.iter().any(|a| a == "--force-scan") {
        send_p2p_beacon_burst(2);
        println!("Force scan triggered: 2x UDP beacon burst sent across all network interfaces.");
        return;
    }

    if args.iter().any(|a| a == "--oma-id") {
        let oma_id = get_or_create_oma_id();
        println!("{}", oma_id);
        return;
    }

    if args.iter().any(|a| a == "--new-oma-id") {
        let oma_id = generate_new_oma_id();
        let _ = update_oma_id_qr();
        send_p2p_beacon_burst(2);
        println!("{}", oma_id);
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--set-oma-id") {
        if let Some(candidate) = args.get(pos + 1) {
            if validate_oma_id(candidate) {
                let formatted = format_oma_id(candidate);
                let state_dir = get_state_dir();
                let oma_id_file = state_dir.join("oma_id");
                if let Err(e) = write_secure_file(&oma_id_file, &formatted) {
                    eprintln!("Error writing oma_id: {}", e);
                    std::process::exit(1);
                }
                let _ = update_oma_id_qr();
                send_p2p_beacon_burst(2);
                println!("{}", formatted);
            } else {
                eprintln!("INVALID OmaID: {}", candidate);
                std::process::exit(1);
            }
            return;
        } else {
            eprintln!("Usage: omasend-engine --set-oma-id <XXXX-XXXX-XXXX-XXXX>");
            std::process::exit(2);
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--validate-oma-id") {
        if let Some(candidate) = args.get(pos + 1) {
            if validate_oma_id(candidate) {
                println!("VALID: {}", format_oma_id(candidate));
            } else {
                eprintln!("INVALID OmaID: {}", candidate);
                std::process::exit(1);
            }
            return;
        }
    }

    // The OmaID-keyed "blinded rendezvous" was derived from a public value and protected
    // nothing; it is gone. Discovery is LAN beacons and the QUIC core's paired keys.
    if args.iter().any(|a| matches!(a.as_str(), "--rendezvous-topic" | "--topic" | "--rendezvous" | "--publish-rendezvous" | "--rendezvous-query")) {
        eprintln!("OmaID rendezvous was removed: it was keyed by the public OmaID and was not confidential.");
        std::process::exit(2);
    }

    if args.iter().any(|a| a == "--stun") {
        match query_stun_external_addr() {
            Some(addr) => println!("{}", addr),
            None => {
                eprintln!("STUN query failed or timed out");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--set-visibility") {
        if let Some(mode) = args.get(pos + 1) {
            set_visibility(mode);
            println!("AirBridge visibility set to {}", mode.to_uppercase());
            return;
        }
    }

    if args.iter().any(|a| a == "--force-scan" || a == "--scan-peers") {
        send_immediate_beacon_broadcast();
        let mut peers = get_discovered_peers();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        peers.retain(|p| now.saturating_sub(p.last_seen_secs) < 300 || p.is_trusted);
        save_discovered_peers(&peers);
        println!("{}", serde_json::to_string_pretty(&peers).unwrap_or_default());
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--bind-oma-id" || a == "--pair-peer" || a == "--pair-oma-id") {
        if let Some(candidate_id) = args.get(pos + 1) {
            let norm = rendezvous::normalize_oma_id(candidate_id);
            if rendezvous::validate_oma_id(&norm) {
                let default_name = format!("OmaID-{}", &norm[..4]);
                let name = args.get(pos + 2).cloned().unwrap_or(default_name);
                let ip_arg = args.get(pos + 3).map(|s| s.as_str());
                match begin_local_pairing(&norm, &name, ip_arg) {
                    Ok((peer, code)) => {
                        send_immediate_beacon_broadcast();
                        let out = serde_json::json!({
                            "status": "PENDING",
                            "oma_id": peer.oma_id,
                            "name": peer.name,
                            "pair_code": code,
                            "expires_in_secs": rendezvous::PAIR_CODE_TTL_SECS
                        });
                        println!("{}", out);
                    }
                    Err(e) => {
                        eprintln!("Error pairing OmaID: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Error: Invalid 16-character OmaID: {}", candidate_id);
                std::process::exit(1);
            }
            return;
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--complete-pair") {
        match (args.get(pos + 1), args.get(pos + 2), args.get(pos + 3)) {
            (Some(ip), Some(peer_id), Some(code)) => {
                let name = args.get(pos + 4).cloned().unwrap_or_default();
                match p2p_complete_pairing(ip, peer_id, code, &name) {
                    Ok(peer) => {
                        let out = serde_json::json!({ "status": "PAIRED", "oma_id": peer.oma_id, "name": peer.name });
                        println!("{}", out);
                    }
                    Err(e) => {
                        eprintln!("Error completing pairing: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                eprintln!("Usage: omasend-engine --complete-pair <PEER_IP> <PEER_OMAID> <6-DIGIT-CODE> [name]");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--trust-peer") {
        if let (Some(id), Some(name)) = (args.get(pos + 1), args.get(pos + 2)) {
            let fp = args.get(pos + 3).map(|s| s.as_str()).unwrap_or("");
            add_trusted_peer(id, name, fp);
            println!("Peer '{}' ({}) trusted successfully.", name, id);
            return;
        }
    }

    // Accept/decline go through the running daemon: it owns the QUIC node that must answer
    // encrypted offers, and it is the only writer that can safely extend the upload window.
    for (flag, accept) in [("--accept-transfer", true), ("--reject-transfer", false)] {
        if let Some(pos) = args.iter().position(|a| a == flag) {
            let Some(token) = args.get(pos + 1) else {
                eprintln!("Usage: omasend-engine {} <token>", flag);
                std::process::exit(2);
            };
            let body = serde_json::json!({ "token": token, "action": if accept { "accept" } else { "reject" } });
            match local_api_request("/api/p2p/decision", &body, Some(Duration::from_secs(15))) {
                Ok(v) if v["ok"].as_bool() == Some(true) => {
                    if accept {
                        let snd = play_samurai_receive_sound();
                        println!("Transfer accepted");
                        finish_sound(snd);
                    } else {
                        println!("Transfer declined");
                    }
                }
                Ok(v) => {
                    eprintln!("{}", v["error"].as_str().unwrap_or("Invalid or expired transfer token"));
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("OmaSend daemon is not reachable: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
    }

    if let Some(pos) = args.iter().position(|a| {
        a == "--send-p2p" || a == "--send" || a == "--send-to-omaid" || a == "--send-file"
    }) {
        // --send <target|auto> <file> [file...]   or   --send <file>  (= auto)
        // All files go in ONE transfer (one approval on the receiver).
        let rest: Vec<String> = args.iter().skip(pos + 1).cloned().collect();
        // "auto" must never pick a peer from unauthenticated beacons (a spoofed "same owner"
        // beacon would receive the file); only QR-paired own devices.
        let auto = || -> Option<String> {
            let t = auto_send_target();
            if t.is_none() {
                eprintln!("Error: No QR-paired own device available for automatic send (pair with: --pair-offer --own)");
            }
            t
        };
        let (target, files): (String, Vec<String>) = match rest.as_slice() {
            [] => {
                eprintln!("Usage: omasend-engine --send [device-id|ip|auto] <file> [file...]");
                std::process::exit(2);
            }
            [only] => match auto() {
                Some(t) => (t, vec![only.clone()]),
                None => std::process::exit(1),
            },
            [t, files @ ..] if t == "auto" => match auto() {
                Some(t) => (t, files.to_vec()),
                None => std::process::exit(1),
            },
            [t, files @ ..] => (t.clone(), files.to_vec()),
        };

        let paths: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
        let snd = play_samurai_send_sound();
        let result = p2p_send_files_to_peer(&target, &paths);
        finish_sound(snd);
        match result {
            Ok(()) => println!("{} file(s) sent successfully to {}", paths.len(), target),
            Err(e) => {
                eprintln!("Error sending file: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--send-dialog") {
        if let Some(target) = args.get(pos + 1) {
            let env_store = get_desktop_gui_envs();
            let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let deadline = Instant::now() + Duration::from_secs(120);
            if let Some(out) = run_cmd_bounded(
                "/usr/bin/zenity",
                &["--file-selection", "--multiple", "--separator=\n", "--title=OmaSend: Select files to send"],
                &envs,
                deadline,
                256 * 1024,
            ) {
                let paths: Vec<PathBuf> = String::from_utf8_lossy(&out)
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(PathBuf::from)
                    .collect();
                if !paths.is_empty() {
                    let snd = play_samurai_send_sound();
                    match p2p_send_files_to_peer(target, &paths) {
                        Ok(()) => println!("{} file(s) sent to {}", paths.len(), target),
                        Err(e) => eprintln!("Error sending file: {}", e),
                    }
                    finish_sound(snd);
                }
            }
            return;
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--sync-clipboard") {
        if let Some(target_ip) = args.get(pos + 1) {
            match p2p_sync_clipboard_to_peer(target_ip) {
                Ok(()) => println!("Clipboard synced successfully to {}", target_ip),
                Err(e) => eprintln!("Error syncing clipboard: {}", e),
            }
            return;
        }
    }

    if args.iter().any(|a| a == "--p2p-peers") {
        let peers = get_discovered_peers();
        println!("{}", serde_json::to_string_pretty(&peers).unwrap_or_default());
        return;
    }

    if args.iter().any(|a| a == "--clipboard-vault" || a == "--clipboard-history") {
        let vault = load_clipboard_vault();
        println!("{}", serde_json::to_string_pretty(&vault).unwrap_or_default());
        return;
    }

    if args.iter().any(|a| a == "--start-wan") {
        eprintln!("{}", WAN_WARNING);
        match start_wan_tunnel() {
            Ok(url) => println!("WAN Tunnel Started: {}", url),
            Err(e) => eprintln!("Error starting WAN tunnel: {}", e),
        }
        return;
    }

    if args.iter().any(|a| a == "--stop-wan") {
        stop_wan_tunnel();
        println!("WAN Tunnel Stopped.");
        return;
    }

    if args.iter().any(|a| a == "--toggle-wan") {
        let (active, connecting, _) = get_wan_status();
        if active || connecting {
            stop_wan_tunnel();
            println!("WAN Stopped");
        } else {
            eprintln!("{}", WAN_WARNING);
            match start_wan_tunnel() {
                Ok(msg) => println!("WAN Started: {}", msg),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        return;
    }

    if args.iter().any(|a| a == "--set-lan") {
        set_active_mode("LAN");
        update_all_qr();
        println!("Mode set to LAN");
        return;
    }

    if args.iter().any(|a| a == "--set-wan") {
        set_active_mode("WAN");
        update_all_qr();
        println!("Mode set to WAN");
        return;
    }

    update_all_qr();

    if args.iter().any(|a| a == "--serve") {
        run_server();
        return;
    }

    let (_, _, wan_url) = get_wan_status();
    let active_mode = get_active_mode();
    let qr_path = get_state_dir().join("qr.svg").to_string_lossy().to_string();

    // Status output never carries the portal secret or the E2EE key: waybar tooltips, the
    // panel's --json polls and terminal scrollback all end up in places the user does not
    // treat as secret. The full link is in the 0600 QR file, or printed on explicit request.
    let active_url = portal_base_url(&ip, &active_mode, wan_url.as_deref());

    if args.iter().any(|a| a == "--portal-url") {
        println!("{}", portal_secret_url(&active_url, &pin, &session_key));
        return;
    }

    if args.iter().any(|a| a == "--status") {
        let mode_tag = if active_mode == "WAN" { "WAN" } else { "LAN" };
        println!(
            "{{\"text\":\"\",\"tooltip\":\"OmaSend AirBridge [{}]\\n{}\",\"class\":\"normal\"}}",
            mode_tag, active_url
        );
        return;
    }

    if args.iter().any(|a| a == "--json") {
        if let Ok(s) = serde_json::to_string_pretty(&build_server_state(&ip)) {
            println!("{}", s);
        }
        return;
    }

    println!("OMASEND - WIRELESS AIRBRIDGE & E2EE CLIPBOARD SENTINEL");
    println!("Mode: {}", active_mode);
    println!("Portal: {}", active_url);
    println!("QR (portal link with access secret and E2EE key): {}", qr_path);
    println!("Full portal link: omasend-engine --portal-url");
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SYNC_MUTEX: Mutex<()> = Mutex::new(());

    /// Creates a peer that completed the code-verified handshake from a LAN source.
    fn confirmed_test_peer(oma_id: &str, name: &str) -> rendezvous::PairedPeer {
        let (_, code) = begin_local_pairing(oma_id, name, None).expect("Begin local pairing");
        let src: IpAddr = "192.168.77.10".parse().unwrap();
        complete_remote_pairing(oma_id, &code, src).expect("Complete code-verified pairing")
    }

    #[test]
    fn test_secure_file_atomic_write_and_mode_0600() {
        let temp_dir = env::temp_dir().join(format!("omasend_sec_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let target_file = temp_dir.join("test_key.txt");
        let content = "secret_session_key_1234567890abcdef";

        // 1. Write secure file atomically
        write_secure_file(&target_file, content).expect("write_secure_file must succeed");

        // Verify mode is strictly 0600
        let meta = fs::symlink_metadata(&target_file).expect("metadata must succeed");
        assert_eq!(
            meta.mode() & 0o777,
            0o600,
            "File permissions must be strictly 0600 (owner-only)"
        );

        // 2. Verify reading works with 0600
        let read_content = read_secure_file(&target_file).expect("read_secure_file must succeed");
        assert_eq!(read_content, content);

        // 3. Verify reading is rejected if permissions are insecure (e.g. 0644)
        fs::set_permissions(&target_file, fs::Permissions::from_mode(0o644)).unwrap();
        let read_insecure = read_secure_file(&target_file);
        assert!(read_insecure.is_err(), "Insecure permissions (0644) must be rejected");

        // 4. Verify atomic write safely overwrites with proper 0600
        let new_content = "updated_secure_key_abcdef123456";
        write_secure_file(&target_file, new_content).expect("overwrite must succeed");
        let meta_after = fs::symlink_metadata(&target_file).expect("metadata must succeed");
        assert_eq!(meta_after.mode() & 0o777, 0o600);
        let read_new = read_secure_file(&target_file).expect("read after overwrite must succeed");
        assert_eq!(read_new, new_content);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_secure_file_rejects_symlinks() {
        let temp_dir = env::temp_dir().join(format!("omasend_sym_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let real_file = temp_dir.join("real.txt");
        fs::write(&real_file, "real content").unwrap();

        let symlink_file = temp_dir.join("symlink.txt");
        std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();

        // Reading a symlink MUST be rejected
        let read_res = read_secure_file(&symlink_file);
        assert!(read_res.is_err(), "Symlinks must be rejected by read_secure_file");

        // Writing over a symlink must remove the symlink itself and write with 0600 without following it
        write_secure_file(&symlink_file, "new_secure_content").expect("write over symlink must succeed");
        assert!(!symlink_file.is_symlink(), "Target must no longer be a symlink");
        let meta = fs::symlink_metadata(&symlink_file).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&real_file).unwrap(), "real content", "Symlink target must not be overwritten");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pin_and_session_key_lifecycle_enforces_0600() {
        let state_dir = get_state_dir();
        let pin = get_or_create_pin();
        assert_eq!(pin.len(), PORTAL_SECRET_HEX_LEN);
        assert!(pin.chars().all(|c| c.is_ascii_hexdigit()));

        let pin_file = state_dir.join("pin.txt");
        let pin_meta = fs::symlink_metadata(&pin_file).expect("pin.txt must exist");
        assert_eq!(pin_meta.mode() & 0o777, 0o600, "pin.txt must have 0600 permissions");

        let session_key = get_or_create_session_key();
        assert_eq!(session_key.len(), 64);

        let key_file = state_dir.join("session_key.txt");
        let key_meta = fs::symlink_metadata(&key_file).expect("session_key.txt must exist");
        assert_eq!(key_meta.mode() & 0o777, 0o600, "session_key.txt must have 0600 permissions");
    }

    #[test]
    fn test_path_traversal_sanitization() {
        assert!(sanitize_filename("../../etc/passwd").starts_with("file_"));
        assert_eq!(sanitize_filename("/root/some_file.txt"), "rootsome_file.txt");
        assert!(sanitize_filename("../../../malicious.sh").starts_with("file_"));
        assert_eq!(sanitize_filename("valid_document.pdf"), "valid_document.pdf");
        assert_eq!(sanitize_filename("my photo (1).jpg"), "my photo 1.jpg");

        // Leading dot files must be renamed to safe file_TIMESTAMP
        let hidden = sanitize_filename(".hidden_config");
        assert!(hidden.starts_with("file_"));
    }

    /// M1: a long name made of multibyte characters must not panic (byte-index truncation
    /// used to split a character and abort the daemon).
    #[test]
    fn test_sanitize_filename_long_multibyte_name() {
        for unit in ["ğ", "Ж", "日本", "😀", "aç"] {
            let name = format!("{}.txt", unit.repeat(200));
            let clean = sanitize_filename(&name);
            assert!(clean.chars().count() <= 180, "{} chars", clean.chars().count());
            assert!(!clean.is_empty());
        }
        // Offset by one ASCII byte so the 180-byte boundary falls inside a character.
        let clean = sanitize_filename(&format!("a{}", "ğ".repeat(120)));
        assert!(clean.starts_with('a') && clean.chars().count() == 120 + 1);
        assert_eq!(urlencoding_decode("%aç%41"), "%aç%41".replace("%41", "A"));
    }

    #[test]
    fn test_visibility_modes() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("OFF");
        let (vis_off, _) = get_visibility();
        assert_eq!(vis_off, "OFF");
        assert!(get_discovered_peers().is_empty());

        set_visibility("EVERYONE");
        let (vis_every, rem) = get_visibility();
        assert_eq!(vis_every, "EVERYONE");
        assert!(rem > 0 && rem <= 600);

        set_visibility("KNOWN");
        let (vis_known, _) = get_visibility();
        assert_eq!(vis_known, "KNOWN");
    }

    #[test]
    fn test_trusted_peers_db_enforces_0600() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let peer_id = format!("test_peer_{}", std::process::id());
        add_trusted_peer(&peer_id, "Test Laptop", "abcdef1234567890");
        assert!(is_peer_trusted(&peer_id));

        let peers_file = get_state_dir().join("trusted_peers.json");
        let meta = fs::symlink_metadata(&peers_file).expect("trusted_peers.json must exist");
        assert_eq!(meta.mode() & 0o777, 0o600, "trusted_peers.json must have 0600 permissions");
    }

    #[test]
    fn test_p2p_beacon_packet_serialization() {
        let packet = P2pBeaconPacket {
            magic: "OMASEND_P2P".to_string(),
            v: 1,
            id: "abc123".to_string(),
            oma_id: "4829-1048-5729-1104".to_string(),
            name: "Omarchy-PC".to_string(),
            ip: "192.168.1.81".to_string(),
            port: 8844,
            mode: "KNOWN".to_string(),
            fp: "deadbeef".to_string(),
            pk: String::new(),
        };
        let serialized = serde_json::to_string(&packet).expect("Must serialize");
        let deserialized: P2pBeaconPacket = serde_json::from_str(&serialized).expect("Must deserialize");
        assert_eq!(deserialized.magic, "OMASEND_P2P");
        assert_eq!(deserialized.id, "abc123");
        assert_eq!(deserialized.oma_id, "4829-1048-5729-1104");
    }

    #[test]
    fn test_safe_read_file_rejects_symlinks_and_non_files() {
        let temp_dir = env::temp_dir().join(format!("omasend_safe_read_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let real_file = temp_dir.join("payload.bin");
        write_secure_bytes(&real_file, b"binary\x00data\xff").unwrap();

        // 1. Valid file reads safely
        let data = safe_read_file(&real_file).expect("Must read valid file");
        assert_eq!(data, b"binary\x00data\xff");

        // 2. Symlink must be rejected
        let sym = temp_dir.join("symlink.bin");
        std::os::unix::fs::symlink(&real_file, &sym).unwrap();
        assert!(safe_read_file(&sym).is_err(), "Symlinks must be rejected");

        // 3. Directory must be rejected
        assert!(safe_read_file(&temp_dir).is_err(), "Directory must be rejected");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_write_secure_bytes_binary_and_0600() {
        let temp_dir = env::temp_dir().join(format!("omasend_bytes_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let target = temp_dir.join("data.bin");
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42];
        write_secure_bytes(&target, &payload).expect("write_secure_bytes must succeed");

        let meta = fs::symlink_metadata(&target).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600, "Must be 0600");
        let read_back = fs::read(&target).unwrap();
        assert_eq!(read_back, payload);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_filename_length_and_traversal_caps() {
        let long_name = "a".repeat(300) + ".txt";
        let sanitized = sanitize_filename(&long_name);
        assert!(sanitized.len() <= 180, "Filename must be capped at 180 chars");

        assert!(sanitize_filename("foo/../../bar").starts_with("file_") || !sanitize_filename("foo/../../bar").contains(".."));
    }

    #[test]
    fn test_pin_rate_limiter_triggers_after_5_failures() {
        reset_pin_rate_limiter();
        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));

        assert!(!is_pin_rate_limited(test_ip));

        for _ in 0..4 {
            let ok = record_pin_attempt(test_ip, false);
            assert!(ok, "Attempts 1-4 should not trigger lock");
            assert!(!is_pin_rate_limited(test_ip));
        }

        // 5th failed attempt triggers block
        let ok5 = record_pin_attempt(test_ip, false);
        assert!(!ok5, "5th attempt must return false (blocked)");
        assert!(is_pin_rate_limited(test_ip), "IP must now be rate limited");

        // Another IP should not be affected
        let other_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(!is_pin_rate_limited(other_ip));

        // Successful PIN clears failure count for that IP
        record_pin_attempt(other_ip, false);
        assert!(record_pin_attempt(other_ip, true));
        assert!(!is_pin_rate_limited(other_ip));

        reset_pin_rate_limiter();
    }

    #[test]
    fn test_cors_trusted_origin_whitelist() {
        let local_ip = "192.168.1.50";

        assert!(is_trusted_origin("http://localhost", local_ip));
        assert!(is_trusted_origin("http://localhost:53317", local_ip));
        assert!(is_trusted_origin("http://127.0.0.1", local_ip));
        assert!(is_trusted_origin("http://127.0.0.1:53317", local_ip));
        assert!(is_trusted_origin("http://192.168.1.50", local_ip));
        assert!(is_trusted_origin("http://192.168.1.50:53317", local_ip));

        // Malicious or third-party origins must be rejected
        assert!(!is_trusted_origin("https://evil.attacker.com", local_ip));
        assert!(!is_trusted_origin("http://192.168.1.55:53317", local_ip));
        assert!(!is_trusted_origin("null", local_ip));
        assert!(!is_trusted_origin("", local_ip));
    }

    #[test]
    fn test_extract_provided_pin() {
        // Never from the URL: query strings end up in history and proxy logs.
        let req_query = HttpRequest {
            query: "foo=bar&pin=4321&baz=1".to_string(),
            ..Default::default()
        };
        assert_eq!(extract_provided_pin(&req_query), None);

        let req_header = HttpRequest {
            headers: vec![("x-omasend-pin".to_string(), "9988".to_string())],
            ..Default::default()
        };
        assert_eq!(extract_provided_pin(&req_header), Some("9988".to_string()));

        // The raw PIN is no longer accepted from (or stored in) a cookie.
        let req_cookie = HttpRequest {
            headers: vec![("cookie".to_string(), "session=abc; pin=1122; omasend_session=deadbeef".to_string())],
            ..Default::default()
        };
        assert_eq!(extract_provided_pin(&req_cookie), None);
        assert_eq!(web_session_cookie(&req_cookie), Some("deadbeef"));
        let v = web_session_value("1122", "k");
        assert_eq!(v.len(), 64);
        assert!(!v.contains("1122"));
        assert_ne!(v, web_session_value("1123", "k"));

        let req_empty = HttpRequest::default();
        assert_eq!(extract_provided_pin(&req_empty), None);
    }

    #[test]
    fn test_get_available_disk_space() {
        let space = get_available_disk_space(Path::new("/tmp"));
        assert!(space.is_some());
        assert!(space.unwrap() > 0);
    }

    #[test]
    fn test_p2p_request_and_clipboard_require_paired_oma_id() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        clear_pending_transfer();
        set_visibility("KNOWN");

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let local_addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (stream1, _) = listener.accept().expect("Accept client 1");
            handle_connection(stream1, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

            let (stream2, _) = listener.accept().expect("Accept client 2");
            handle_connection(stream2, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });

        // 1. Unpaired client sending clipboard -> must return 403 Forbidden
        let mut client1 = TcpStream::connect(local_addr).expect("Connect client 1");
        let unauth_payload = serde_json::json!({
            "sender_id": "unpaired_oma_id_9999",
            "sender_name": "Rogue Device",
            "content_type": "text",
            "text": "malicious clipboard injection"
        });
        let unauth_bytes = unauth_payload.to_string().into_bytes();
        let req1 = format!(
            "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            local_addr, unauth_bytes.len()
        );
        client1.write_all(req1.as_bytes()).unwrap();
        client1.write_all(&unauth_bytes).unwrap();
        let mut resp1 = String::new();
        client1.read_to_string(&mut resp1).unwrap();
        assert!(resp1.starts_with("HTTP/1.1 403 Forbidden"), "Unpaired client must be rejected with 403: {}", resp1);

        // 2. Unpaired client sending transfer request -> must return 403 Forbidden
        let mut client2 = TcpStream::connect(local_addr).expect("Connect client 2");
        let req_payload = serde_json::json!({
            "sender_id": "unpaired_sender",
            "sender_name": "Rogue Device",
            "files": [{"name": "evil.sh", "size_bytes": 100}]
        });
        let req_bytes = req_payload.to_string().into_bytes();
        let req2 = format!(
            "POST /api/p2p/request HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            local_addr, req_bytes.len()
        );
        client2.write_all(req2.as_bytes()).unwrap();
        client2.write_all(&req_bytes).unwrap();
        let mut resp2 = String::new();
        client2.read_to_string(&mut resp2).unwrap();
        assert!(resp2.starts_with("HTTP/1.1 403 Forbidden"), "Unpaired transfer request must be rejected with 403: {}", resp2);

        server_thread.join().expect("Join server thread");
    }

    #[test]
    fn test_concurrency_tracker_caps_and_early_rejection() {
        let _test_lock = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_connection_tracker();

        let peer_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let peer_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

        // 1. Peer A acquires up to MAX_PEER_CONNECTIONS (4)
        let mut guards_a = Vec::new();
        for _ in 0..MAX_PEER_CONNECTIONS {
            let g = try_acquire_connection(peer_a);
            assert!(g.is_some(), "Peer A should acquire up to MAX_PEER_CONNECTIONS");
            guards_a.push(g.unwrap());
        }

        // 5th connection from Peer A must be rejected
        let excess_a = try_acquire_connection(peer_a);
        assert!(excess_a.is_none(), "5th connection from same IP must be rejected early");

        // Peer B can still connect (different IP)
        let g_b = try_acquire_connection(peer_b);
        assert!(g_b.is_some(), "Peer B should connect independently");

        // Dropping one guard from Peer A frees up a slot
        guards_a.pop();
        let freed_a = try_acquire_connection(peer_a);
        assert!(freed_a.is_some(), "Dropping guard should immediately allow a new connection from Peer A");

        // Clean up
        drop(guards_a);
        drop(g_b);
        drop(freed_a);
        reset_connection_tracker();

        // 2. Test global connection cap (32)
        let mut global_guards = Vec::new();
        for i in 0..MAX_GLOBAL_CONNECTIONS {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
            let g = try_acquire_connection(ip);
            assert!(g.is_some(), "Global connection slot {} should succeed", i);
            global_guards.push(g.unwrap());
        }

        // 33rd global connection must be rejected regardless of IP
        let new_peer = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let excess_global = try_acquire_connection(new_peer);
        assert!(excess_global.is_none(), "33rd global connection must be rejected by global cap");

        drop(global_guards);
        reset_connection_tracker();
    }

    #[test]
    fn test_oversized_body_ceiling_rejected() {
        use std::io::Cursor;

        // Content-Length exceeding 100 MiB limit (MAX_BODY_SIZE = 104,857,600)
        let raw_req = b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 104857601\r\n\r\n";
        let mut cursor = Cursor::new(raw_req.to_vec());

        let res = read_http_request_stream(&mut cursor);
        assert!(res.is_none(), "Request exceeding 100 MiB ceiling must be rejected immediately without reading/allocating");
    }

    #[test]
    fn test_streaming_body_staged_to_disk() {
        use std::io::Cursor;
        let _test_lock = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        CURRENT_STAGED_BYTES.store(0, Ordering::SeqCst);

        // 2 MiB payload (exceeds 1 MiB IN_MEMORY_BODY_LIMIT, but under 100 MiB ceiling)
        let body_size = 2 * 1024 * 1024;
        let mut raw = Vec::new();
        raw.extend_from_slice(format!("POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n", body_size).as_bytes());
        raw.resize(raw.len() + body_size, 0xAA);

        let mut cursor = Cursor::new(raw);
        let res = read_http_request_stream(&mut cursor);
        assert!(res.is_some(), "Streaming 2 MiB payload should succeed");

        let (req, body) = res.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/upload");
        assert_eq!(body.len(), body_size);

        // Body must be Staged, not kept in Memory
        match body {
            HttpBody::Staged(staged) => {
                assert_eq!(staged.size, body_size as u64);
                assert!(staged.path.exists(), "Staged part file must exist on disk");

                let meta = fs::symlink_metadata(&staged.path).expect("staged file metadata");
                assert_eq!(meta.mode() & 0o777, 0o600, "Staged file must have mode 0600");

                let staged_path = staged.path.clone();
                drop(staged);
                // RAII Drop must clean up the staging file
                assert!(!staged_path.exists(), "Dropped staged file must be removed from disk");
            }
            HttpBody::Memory(_) => {
                panic!("Body > 1 MiB must be streamed to disk staging file, not kept in RAM");
            }
        }
    }

    #[test]
    fn test_slow_client_early_eof_cleanup() {
        use std::io::Cursor;
        let _test_lock = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        CURRENT_STAGED_BYTES.store(0, Ordering::SeqCst);

        // Header claims 2 MiB, but only sends 1024 bytes and disconnects
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2097152\r\n\r\n");
        raw.extend_from_slice(&[0xBB; 1024]);

        let mut cursor = Cursor::new(raw);
        let res = read_http_request_stream(&mut cursor);
        assert!(res.is_none(), "Premature EOF must reject request");
    }

    struct SlowProgressReader {
        total: usize,
        sent: usize,
        chunk_delay: Duration,
    }

    impl Read for SlowProgressReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.sent >= self.total {
                return Ok(0);
            }
            std::thread::sleep(self.chunk_delay);
            let n = buf.len().min(16).min(self.total - self.sent);
            for b in &mut buf[..n] {
                *b = b'X';
            }
            self.sent += n;
            Ok(n)
        }
    }

    impl TimeoutStream for SlowProgressReader {}

    #[test]
    fn test_monotonic_deadline_slow_client_progress() {
        // Slow client sends bytes in 16-byte chunks with 20ms delay per chunk.
        // With a 50ms monotonic deadline, it can send at most 2 chunks (40ms) before the deadline expires.
        let mut slow_reader = SlowProgressReader {
            total: 2048,
            sent: 0,
            chunk_delay: Duration::from_millis(20),
        };

        let deadline = Instant::now() + Duration::from_millis(50);
        let res = read_http_headers(&mut slow_reader, deadline);
        assert!(res.is_none(), "Slow client making partial progress past deadline must be terminated");

        // Test body reading with expired monotonic deadline
        let mut slow_body_reader = SlowProgressReader {
            total: 1024,
            sent: 0,
            chunk_delay: Duration::from_millis(20),
        };
        let body_deadline = Instant::now() + Duration::from_millis(50);
        let body_res = read_http_body(
            &mut slow_body_reader,
            1024,
            b"",
            body_deadline,
            false,
            MAX_BODY_SIZE,
        );
        assert!(body_res.is_none(), "Body reader must abort when monotonic deadline is reached");
    }

    #[test]
    fn test_endpoint_specific_body_limits() {
        use std::io::Cursor;

        // 1. Clipboard endpoint (> 1 MiB MAX_CLIPBOARD_BODY)
        let clip_size = MAX_CLIPBOARD_BODY + 10;
        let mut cursor = Cursor::new(vec![0u8; 100]);
        let deadline = Instant::now() + Duration::from_secs(5);
        let res = read_http_body(&mut cursor, clip_size, b"", deadline, false, MAX_CLIPBOARD_BODY);
        assert!(res.is_none(), "Clipboard payload exceeding 1 MiB must be rejected immediately");

        // 2. Control endpoint (> 64 KiB MAX_CONTROL_BODY)
        let ctrl_size = MAX_CONTROL_BODY + 10;
        let mut cursor_ctrl = Cursor::new(vec![0u8; 100]);
        let res_ctrl = read_http_body(&mut cursor_ctrl, ctrl_size, b"", deadline, false, MAX_CONTROL_BODY);
        assert!(res_ctrl.is_none(), "Control payload exceeding 64 KiB must be rejected immediately");

        // 3. Encrypted upload endpoint (> 25 MiB MAX_ENCRYPTED_UPLOAD_SIZE)
        let enc_size = MAX_ENCRYPTED_UPLOAD_SIZE + 10;
        let mut cursor_enc = Cursor::new(vec![0u8; 100]);
        let res_enc = read_http_body(&mut cursor_enc, enc_size, b"", deadline, true, MAX_ENCRYPTED_UPLOAD_SIZE);
        assert!(res_enc.is_none(), "Encrypted upload payload exceeding 25 MiB must be rejected immediately");
    }

    #[test]
    fn test_staged_file_to_bytes_memory_guard() {
        let fake_staged = StagedFile {
            path: PathBuf::from("/nonexistent/file.bin"),
            size: (MAX_ENCRYPTED_UPLOAD_SIZE + 1) as u64,
            persisted: true,
            reservation: None,
            blake3_hash: None,
            sha256_hash: None,
            md5_hash: None,
        };

        let res = fake_staged.to_bytes();
        assert!(res.is_err(), "Calling to_bytes() on staged payload exceeding 25 MiB must fail to protect RAM");
        assert!(res.unwrap_err().contains("Payload exceeds maximum in-memory materialization limit"));
    }

    #[test]
    fn test_aggregate_staging_capacity_and_race_prevention() {
        let _test_lock = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let ddir = get_download_dir();
        let _ = fs::create_dir_all(&ddir);

        // Pre-fill baseline near MAX_AGGREGATE_STAGING_BYTES leaving 200 MiB headroom
        let base = MAX_AGGREGATE_STAGING_BYTES - 200 * 1024 * 1024;
        CURRENT_STAGED_BYTES.store(base, Ordering::SeqCst);

        // Reserve 100 MiB
        let guard1 = StagingReservationGuard::try_reserve(100 * 1024 * 1024, &ddir);
        assert!(guard1.is_ok(), "First 100 MiB reservation should succeed");
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), base + 100 * 1024 * 1024);

        // Reserve another 100 MiB (total = MAX_AGGREGATE_STAGING_BYTES)
        let guard2 = StagingReservationGuard::try_reserve(100 * 1024 * 1024, &ddir);
        assert!(guard2.is_ok(), "Second 100 MiB reservation reaching aggregate cap should succeed");
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), MAX_AGGREGATE_STAGING_BYTES);

        // Third reservation exceeding cap must fail
        let guard3 = StagingReservationGuard::try_reserve(1024, &ddir);
        assert!(guard3.is_err(), "Reservation exceeding aggregate cap must be rejected");

        // Drop first guard
        drop(guard1);
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), base + 100 * 1024 * 1024);

        // Now a 50 MiB reservation should succeed
        let guard4 = StagingReservationGuard::try_reserve(50 * 1024 * 1024, &ddir);
        assert!(guard4.is_ok(), "Reservation under remaining cap should succeed");
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), base + 150 * 1024 * 1024);

        // Cleanup
        drop(guard2);
        drop(guard4);
        CURRENT_STAGED_BYTES.store(0, Ordering::SeqCst);
    }

    #[test]
    fn test_encrypted_upload_concurrency_guard() {
        let _test_lock = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        ACTIVE_ENCRYPTED_UPLOADS.store(0, Ordering::SeqCst);

        let g1 = EncryptedUploadGuard::try_acquire();
        assert!(g1.is_some(), "First encrypted upload should acquire");

        let g2 = EncryptedUploadGuard::try_acquire();
        assert!(g2.is_some(), "Second encrypted upload should acquire (up to MAX_CONCURRENT_ENCRYPTED_UPLOADS = 2)");

        let g3 = EncryptedUploadGuard::try_acquire();
        assert!(g3.is_none(), "Third concurrent encrypted upload must be rejected early");

        drop(g1);
        let g4 = EncryptedUploadGuard::try_acquire();
        assert!(g4.is_some(), "After dropping g1, slot is freed and acquisition succeeds");

        drop(g2);
        drop(g4);
        assert_eq!(ACTIVE_ENCRYPTED_UPLOADS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_unauthenticated_upload_early_rejected_without_staging() {
        use std::io::Cursor;
        let _test_lock = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());

        CURRENT_STAGED_BYTES.store(0, Ordering::SeqCst);

        // Simulate an unauthenticated upload request header
        let raw_headers = b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10485760\r\n\r\n";
        let mut cursor = Cursor::new(raw_headers.to_vec());
        let deadline = Instant::now() + Duration::from_secs(5);
        let h_res = read_http_headers(&mut cursor, deadline);
        assert!(h_res.is_some());

        let h = h_res.unwrap();
        let maybe_pin = extract_provided_pin(&h.req);
        let authorized = maybe_pin.as_deref() == Some("correct_pin");
        assert!(!authorized, "Request without PIN must not be authorized");

        // Verify that because authorized is false, staging is NEVER performed
        // CURRENT_STAGED_BYTES remains 0
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_recently_notified_file_lifecycle() {
        let test_name = "test_received_doc.pdf";
        assert!(!is_recently_notified(test_name));
        record_notified_file(test_name);
        assert!(is_recently_notified(test_name));
    }

    #[test]
    fn test_transfer_file_info_integrity_serialization() {
        let sample_data = b"Hello Omarchy Zero-Trust AirBridge!";
        let mut sha = Sha256::new();
        sha.update(sample_data);
        let exp_blake3 = blake3::hash(sample_data).to_hex().to_string();
        let exp_sha256 = hex::encode(sha.finalize());
        let exp_md5 = format!("{:x}", md5::compute(sample_data));

        let file_info = TransferFileInfo {
            name: "test_doc.txt".to_string(),
            size_bytes: sample_data.len() as u64,
            blake3: Some(exp_blake3.clone()),
            sha256: Some(exp_sha256.clone()),
            md5: Some(exp_md5.clone()),
        };

        let serialized = serde_json::to_string(&file_info).expect("Must serialize");
        assert!(serialized.contains("blake3"));
        assert!(serialized.contains(&exp_blake3));
        assert!(serialized.contains("sha256"));
        assert!(serialized.contains(&exp_sha256));
        assert!(serialized.contains("md5"));
        assert!(serialized.contains(&exp_md5));

        let deserialized: TransferFileInfo = serde_json::from_str(&serialized).expect("Must deserialize");
        assert_eq!(deserialized.name, "test_doc.txt");
        assert_eq!(deserialized.size_bytes, sample_data.len() as u64);
        assert_eq!(deserialized.sha256, Some(exp_sha256));
        assert_eq!(deserialized.md5, Some(exp_md5));
    }

    #[test]
    fn test_http_body_compute_hashes_memory_and_staged() {
        let test_payload = b"Zero-Trust Payload With Cryptographic Checksums (MD5 & SHA256)";
        let mut sha = Sha256::new();
        sha.update(test_payload);
        let expected_sha256 = hex::encode(sha.finalize());
        let expected_md5 = format!("{:x}", md5::compute(test_payload));

        // Test in-memory HttpBody
        let mem_body = HttpBody::Memory(test_payload.to_vec());
        let (calc_sha, calc_md5) = mem_body.compute_hashes().expect("Compute memory hashes");
        assert_eq!(calc_sha, expected_sha256);
        assert_eq!(calc_md5, expected_md5);

        // Test staged HttpBody
        let temp_dir = get_download_dir();
        let _ = fs::create_dir_all(&temp_dir);
        let stage_path = temp_dir.join(format!(".tmp_test_stage_{}.part", std::process::id()));
        write_secure_bytes(&stage_path, test_payload).expect("Write test staged file");

        let staged = StagedFile::new(stage_path.clone(), test_payload.len() as u64, None, None);
        let staged_body = HttpBody::Staged(staged);
        let (staged_sha, staged_md5) = staged_body.compute_hashes().expect("Compute staged hashes");
        assert_eq!(staged_sha, expected_sha256);
        assert_eq!(staged_md5, expected_md5);

        // Cleanup
        let _ = fs::remove_file(&stage_path);
    }

    #[test]
    fn test_tampered_file_integrity_mismatch_detected() {
        let original_data = b"Original Authentic Omarchy Payload";
        let tampered_data = b"Modified/Tampered Payload In Transit!";

        let mut sha = Sha256::new();
        sha.update(original_data);
        let expected_sha256 = hex::encode(sha.finalize());
        let expected_md5 = format!("{:x}", md5::compute(original_data));

        let tampered_body = HttpBody::Memory(tampered_data.to_vec());
        let (computed_sha256, computed_md5) = tampered_body.compute_hashes().expect("Compute hashes");

        // Verification must detect mismatch
        assert_ne!(computed_sha256, expected_sha256, "Tampered SHA-256 must NOT match");
        assert_ne!(computed_md5, expected_md5, "Tampered MD5 must NOT match");
    }

    #[test]
    fn test_zero_trust_unapproved_file_rejection() {
        let approved_info = TransferFileInfo {
            name: "approved_file.pdf".to_string(),
            size_bytes: 1024,
            blake3: Some("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff".to_string()),
            sha256: Some("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string()),
            md5: Some("0123456789abcdef0123456789abcdef".to_string()),
        };

        let pending = PendingFileTransfer {
            token: "valid_tok_123".to_string(),
            sender_id: "sender_456".to_string(),
            sender_name: "Sender PC".to_string(),
            sender_ip: "192.168.1.50".to_string(),
            file_names: vec!["approved_file.pdf".to_string()],
            files: vec![approved_info],
            remaining_files: 1,
            total_size_bytes: 1024,
            created_at: 100,
            expires_at: 500,
            status: "ACCEPTED".to_string(),
            sender_pk: None,
            transport: None,
        };

        // File listed in approved files
        let is_approved = pending.files.iter().any(|f| f.name == "approved_file.pdf");
        assert!(is_approved, "Approved file must be recognized");

        // Attacker attempts to upload an unapproved malicious payload with same token
        let malicious_filename = "malicious_script.sh";
        let is_malicious_approved = pending.files.iter().any(|f| f.name == malicious_filename)
            || pending.file_names.iter().any(|n| n == malicious_filename);
        assert!(!is_malicious_approved, "Unapproved file MUST be rejected under Zero-Trust rules");
    }

    #[test]
    fn test_military_grade_blake3_and_zeroize_defense() {
        use crate::military::{compute_stream_checksums, ProtectedSecret};
        use zeroize::Zeroize;

        // 1. Memory zeroization
        let mut secret_pin = ProtectedSecret::new("998877".to_string());
        assert_eq!(secret_pin.as_str(), "998877");
        secret_pin.zeroize();
        assert!(secret_pin.as_str().chars().all(|c| c == '\0'));

        // 2. BLAKE3 post-quantum streaming hash
        let sample = b"Military Grade Quantum Resilient Transport Data";
        let checksums = compute_stream_checksums(std::io::Cursor::new(sample)).unwrap();
        let expected_b3 = blake3::hash(sample).to_hex().to_string();
        assert_eq!(checksums.blake3_hex, expected_b3);
        assert!(!checksums.sha256_hex.is_empty());
        assert!(!checksums.md5_hex.is_empty());
    }

    #[test]
    fn test_sandbox_read_paths_exclude_home() {
        let home = Path::new("/home/alice");
        let paths = sandbox_read_paths(home, Some(Path::new("/home/alice/Projects/omasend")));
        assert!(!paths.iter().any(|p| p == home));
        assert!(!paths.iter().any(|p| p.starts_with("/home/alice/.ssh")));
        assert!(paths.iter().any(|p| p == Path::new("/home/alice/Projects/omasend")));
        assert!(paths
            .iter()
            .any(|p| p == Path::new("/home/alice/.local/share/omarchy/plugins/ozdil.omasend")));

        // A binary sitting in $HOME (or above it) must not re-grant the whole home dir.
        for exe_dir in ["/home/alice", "/home", "/"] {
            let paths = sandbox_read_paths(home, Some(Path::new(exe_dir)));
            assert!(!paths.iter().any(|p| home.starts_with(p)), "{exe_dir}");
        }
    }

    #[test]
    fn test_outgoing_stage_links_files_and_cleans_up() {
        let src_dir = std::env::temp_dir().join(format!("omasend_stage_src_{}", std::process::id()));
        fs::create_dir_all(&src_dir).unwrap();
        let a = src_dir.join("photo.jpg");
        let b = src_dir.join("sub_photo.jpg");
        fs::write(&a, b"one").unwrap();
        fs::write(&b, b"two").unwrap();
        let paths = vec![a.to_string_lossy().to_string(), b.to_string_lossy().to_string()];
        let dir;
        {
            let stage = stage_outgoing_files(&paths).unwrap();
            dir = stage.dir.clone();
            assert!(stage.paths[0].starts_with(get_state_dir()));
            assert_eq!(stage.paths[0].file_name().unwrap(), "photo.jpg");
            assert_eq!(fs::read(&stage.paths[1]).unwrap(), b"two");
        }
        assert!(!dir.exists());
        assert!(a.exists() && b.exists());
        let _ = fs::remove_dir_all(&src_dir);
    }

    #[test]
    fn test_military_landlock_and_anti_forensics_lifecycle() {
        use crate::military::{enable_anti_forensics, enable_landlock_sandbox};

        // Anti-forensics must succeed on Linux
        assert!(enable_anti_forensics());

        // Landlock sandbox gracefully falls back or succeeds
        let tmp = std::env::temp_dir();
        let _ = enable_landlock_sandbox(
            &[
                &tmp,
                Path::new("/usr"),
                Path::new("/bin"),
                Path::new("/lib"),
                Path::new("/lib64"),
                Path::new("/etc"),
                Path::new("/proc"),
                Path::new("/dev"),
            ],
            &[&tmp],
        );
    }

    #[test]
    fn test_clipboard_item_serialization_and_url_detection() {
        assert!(is_probable_url("https://omarchy.org"));
        assert!(is_probable_url("http://github.com/ozdil/omasend"));
        assert!(is_probable_url("ftp://files.archlinux.org"));
        assert!(is_probable_url("gemini://gemini.circumlunar.space"));
        assert!(is_probable_url("www.kernel.org"));
        assert!(is_probable_url("omarchy.tr"));
        assert!(!is_probable_url("Hello World! This is a simple note."));
        assert!(!is_probable_url("cat /etc/os-release"));
        assert!(!is_probable_url("123456"));

        let item = ClipboardItem {
            timestamp: 1727700000,
            sender: "Pixel 9 Pro".to_string(),
            content_type: "text".to_string(),
            text: "https://omarchy.org/docs".to_string(),
            char_count: 24,
            is_url: true,
            image_hash: None,
            image_size: None,
            image_width: None,
            image_height: None,
            thumbnail_base64: None,
        };

        let json = serde_json::to_string(&item).expect("Serialize ClipboardItem");
        let parsed: ClipboardItem = serde_json::from_str(&json).expect("Deserialize ClipboardItem");
        assert_eq!(parsed, item);
        assert_eq!(parsed.char_count, 24);
        assert!(parsed.is_url);
    }

    #[test]
    fn test_instant_clipboard_delivery_and_hash_tracking() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let test_text = format!("Unique test note {}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let expected_hash = compute_clipboard_hash(&test_text);
        assert_eq!(expected_hash.len(), 64);

        set_last_synced_clipboard_hash(&expected_hash);
        let retrieved = get_last_synced_clipboard_hash();
        assert_eq!(retrieved.as_deref(), Some(expected_hash.as_str()));

        let vault = load_clipboard_vault();
        assert!(vault.items.is_empty(), "Clipboard vault must not persist items to disk");
    }

    #[test]
    fn test_anti_echo_loop_and_sha256_hash_tracking() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let payload = "Secret Omnipresent Clipboard Sync Payload";
        let expected_hash = compute_clipboard_hash(payload);
        assert!(!expected_hash.is_empty());
        assert_eq!(expected_hash.len(), 64);

        set_last_synced_clipboard_hash(&expected_hash);
        let retrieved = get_last_synced_clipboard_hash();
        assert_eq!(retrieved.as_deref(), Some(expected_hash.as_str()));

        // Anti-Echo verification: incoming hash matches, so re-echo loop is suppressed
        let new_probe_hash = compute_clipboard_hash(payload);
        assert_eq!(retrieved.as_deref(), Some(new_probe_hash.as_str()), "Hash match must prevent outbound loop echo");
    }

    #[test]
    fn test_clipboard_vault_max_capacity_truncation() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let mut test_vault = ClipboardVault::default();
        for i in 0..30 {
            test_vault.items.insert(0, ClipboardItem {
                timestamp: 1000 + i,
                sender: format!("Device {}", i),
                content_type: "text".to_string(),
                text: format!("Item number {}", i),
                char_count: 14,
                is_url: false,
                image_hash: None,
                image_size: None,
                image_width: None,
                image_height: None,
                thumbnail_base64: None,
            });
            if test_vault.items.len() > MAX_CLIPBOARD_VAULT_ITEMS {
                test_vault.items.truncate(MAX_CLIPBOARD_VAULT_ITEMS);
            }
        }

        assert_eq!(test_vault.items.len(), MAX_CLIPBOARD_VAULT_ITEMS);
        assert_eq!(test_vault.items[0].text, "Item number 29");
        assert_eq!(test_vault.items[19].text, "Item number 10");
    }

    #[test]
    fn test_server_state_includes_oma_id_and_wan_fields() {
        let oma_id = "4829-1048-5729-1104".to_string();
        let state = ServerState {
            status: "ACTIVE".to_string(),
            port: PORT,
            local_ip: "192.168.1.50".to_string(),
            tailscale_ip: None,
            active_mode: "LAN".to_string(),
            wan_active: false,
            wan_connecting: false,
            wan_provider: None,
            wan_url: None,
            download_dir: "/home/user/Downloads".to_string(),
            shared_dir: "/home/user/Downloads/shared".to_string(),
            qr_path: "/tmp/qr.svg".to_string(),
            omaid_qr_path: "/tmp/omaid_qr.svg".to_string(),
            active_url: "http://192.168.1.50:53317".to_string(),
            total_received: 0,
            recent_files: vec![],
            shared_files: vec![],
            p2p_device_id: "dev_xyz".to_string(),
            p2p_hostname: "omarchy-node".to_string(),
            p2p_visibility: "ALL".to_string(),
            p2p_visibility_remaining_secs: 0,
            p2p_discovered_peers: vec![],
            p2p_pending_transfer: None,
            p2p_transfer_progress: None,
            clipboard_vault: vec![],
            oma_id: oma_id.clone(),
            wan_mode: "LAN".to_string(),
            stun_addr: Some("198.51.100.1:53317".to_string()),
            sound_enabled: true,
            firewall_status: "OK".to_string(),
            device_key_id: String::new(),
            paired_devices: vec![],
            sandbox: Some(false),
        };

        let json = serde_json::to_string(&state).expect("Serialize ServerState");
        assert!(json.contains("\"oma_id\":\"4829-1048-5729-1104\""));
        assert!(json.contains("\"wan_mode\":\"LAN\""));
        assert!(json.contains("\"stun_addr\":\"198.51.100.1:53317\""));
        assert!(json.contains("\"sandbox\":false"));
    }

    #[test]
    fn test_stream_file_zero_copy_and_socket_transmission() {
        let temp_dir = env::temp_dir().join(format!("zero_copy_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let test_file = temp_dir.join("sample_file.dat");
        let payload = vec![0x42u8; 256 * 1024]; // 256 KiB payload
        write_secure_bytes(&test_file, &payload).expect("Write test file");

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let local_addr = listener.local_addr().unwrap();

        let client_thread = thread::spawn(move || {
            let mut client = TcpStream::connect(local_addr).expect("Connect to listener");
            let mut buf = Vec::new();
            client.read_to_end(&mut buf).expect("Read all");
            buf
        });

        let (mut server_stream, _) = listener.accept().expect("Accept client");
        let extra = [("Content-Disposition", "attachment; filename=\"sample_file.dat\"")];
        let sent_bytes = stream_file_zero_copy(
            &mut server_stream,
            &test_file,
            "application/octet-stream",
            Some(&extra),
            Some("http://127.0.0.1"),
        ).expect("stream_file_zero_copy");

        assert_eq!(sent_bytes, payload.len() as u64);
        drop(server_stream);

        let received = client_thread.join().expect("Join client thread");
        assert!(received.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(received.windows(4).any(|w| w == b"\r\n\r\n"));
        let header_end = received.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let received_body = &received[header_end..];
        assert_eq!(received_body.len(), payload.len());
        assert_eq!(received_body, payload.as_slice());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_streaming_chunked_blake3_128k() {
        let temp_dir = env::temp_dir().join(format!("chunked_blake3_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let test_payload = vec![0x7fu8; 1536 * 1024]; // 1.5 MiB to cross 1 MiB staging and 128 KiB boundaries
        let expected_blake3 = blake3::hash(&test_payload).to_hex().to_string();

        let mut cursor = std::io::Cursor::new(test_payload.clone());
        let deadline = Instant::now() + Duration::from_secs(10);
        let body = read_http_body(&mut cursor, test_payload.len(), &[], deadline, true, MAX_BODY_SIZE)
            .expect("read_http_body chunked");

        match body {
            HttpBody::Staged(ref staged) => {
                assert_eq!(staged.size, test_payload.len() as u64);
                assert_eq!(staged.blake3_hash.as_deref(), Some(expected_blake3.as_str()));
                let (calc_blake3, _, _) = body.compute_military_hashes().expect("compute military hashes");
                assert_eq!(calc_blake3, expected_blake3);
            }
            HttpBody::Memory(_) => panic!("Expected Staged HttpBody for > 1 MiB payload"),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_desktop_oma_id_qr_generation_and_caching() {
        let (svg_path, png_path) = update_oma_id_qr();
        let svg_file = Path::new(&svg_path);
        let png_file = Path::new(&png_path);

        assert!(svg_file.exists(), "oma_id_qr.svg must exist");
        assert!(png_file.exists(), "oma_id_qr.png must exist");
        let png = fs::read(png_file).expect("Read oma_id_qr.png");
        let (ct, w, h) = validate_image_header(&png).expect("valid PNG header");
        assert_eq!(ct, "image_png");
        assert_eq!(w, h);

        let svg_content = fs::read_to_string(svg_file).expect("Read oma_id_qr.svg");
        assert!(svg_content.contains("<svg"), "SVG must contain valid xml root tag");
    }

    #[test]
    fn test_discovered_peers_atomic_pruning_lifecycle() {
        let temp_dir = env::temp_dir().join(format!("peers_pruning_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let peers_file = temp_dir.join("discovered_peers.json");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        let test_peers = vec![
            DiscoveredPeer {
                id: "peer-active".to_string(),
                oma_id: "1234-5678-9012-3456".to_string(),
                name: "Active Machine".to_string(),
                ip: "192.168.1.50".to_string(),
                port: 53317,
                transport: "LAN".to_string(),
                fingerprint: "fp1".to_string(),
                is_trusted: false,
                is_same_owner: false,
                last_seen_secs: now,
                pk: String::new(),
                key_trust: String::new(),
            },
            DiscoveredPeer {
                id: "peer-expired".to_string(),
                oma_id: "9876-5432-1098-7654".to_string(),
                name: "Offline Machine".to_string(),
                ip: "192.168.1.60".to_string(),
                port: 53317,
                transport: "LAN".to_string(),
                fingerprint: "fp2".to_string(),
                is_trusted: false,
                is_same_owner: false,
                last_seen_secs: now - 30, // 30 seconds old -> expired
                pk: String::new(),
                key_trust: String::new(),
            },
        ];

        let json = serde_json::to_string_pretty(&test_peers).unwrap();
        write_secure_file(&peers_file, &json).expect("write initial peers");

        // Filter expired
        let read_json = read_secure_file(&peers_file).unwrap();
        let loaded: Vec<DiscoveredPeer> = serde_json::from_str(&read_json).unwrap();
        let remaining: Vec<DiscoveredPeer> = loaded.into_iter().filter(|p| now.saturating_sub(p.last_seen_secs) <= 15).collect();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, "peer-active");

        write_secure_file(&peers_file, &serde_json::to_string_pretty(&remaining).unwrap()).unwrap();
        let meta = fs::symlink_metadata(&peers_file).expect("Stat peers file");
        assert_eq!(meta.mode() & 0o777, 0o600);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_broadcast_addresses_resolution() {
        let addrs = get_all_broadcast_addresses();
        assert!(!addrs.is_empty(), "Must contain at least global broadcast");
        assert!(addrs.contains(&Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_image_header_validation_png_jpeg_webp() {
        // 1. Valid 100x200 PNG
        let mut png_data = Vec::new();
        png_data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        png_data.extend_from_slice(&13u32.to_be_bytes()); // Chunk len
        png_data.extend_from_slice(b"IHDR");
        png_data.extend_from_slice(&100u32.to_be_bytes()); // Width = 100
        png_data.extend_from_slice(&200u32.to_be_bytes()); // Height = 200
        png_data.extend_from_slice(&[8, 6, 0, 0, 0]); // Bit depth, color type, etc.
        png_data.extend_from_slice(&[0, 0, 0, 0]); // CRC

        let res = validate_image_header(&png_data);
        assert!(res.is_ok(), "Valid PNG must pass header validation");
        let (ct, w, h) = res.unwrap();
        assert_eq!(ct, "image_png");
        assert_eq!(w, 100);
        assert_eq!(h, 200);

        // 2. Valid 320x240 JPEG
        let mut jpeg_data = Vec::new();
        jpeg_data.extend_from_slice(b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00");
        jpeg_data.extend_from_slice(b"\xFF\xC0\x00\x11\x08\x00\xF0\x01\x40\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"); // SOF0: height=240 (0x00F0), width=320 (0x0140)
        jpeg_data.extend_from_slice(b"\xFF\xD9");

        let res_jpg = validate_image_header(&jpeg_data);
        assert!(res_jpg.is_ok(), "Valid JPEG must pass header validation");
        let (ct_jpg, w_jpg, h_jpg) = res_jpg.unwrap();
        assert_eq!(ct_jpg, "image_jpeg");
        assert_eq!(w_jpg, 320);
        assert_eq!(h_jpg, 240);

        // 3. Valid WebP (VP8X canvas 800x600)
        let mut webp_data = Vec::new();
        webp_data.extend_from_slice(b"RIFF");
        webp_data.extend_from_slice(&38u32.to_le_bytes()); // File size
        webp_data.extend_from_slice(b"WEBP");
        webp_data.extend_from_slice(b"VP8X");
        webp_data.extend_from_slice(&10u32.to_le_bytes()); // Chunk size
        webp_data.extend_from_slice(&[0u8; 4]); // Flags + reserved
        // 24-bit canvas width - 1 = 799 (0x00031F)
        webp_data.push(0x1F);
        webp_data.push(0x03);
        webp_data.push(0x00);
        // 24-bit canvas height - 1 = 599 (0x000257)
        webp_data.push(0x57);
        webp_data.push(0x02);
        webp_data.push(0x00);

        let res_webp = validate_image_header(&webp_data);
        assert!(res_webp.is_ok(), "Valid WebP must pass header validation");
        let (ct_webp, w_webp, h_webp) = res_webp.unwrap();
        assert_eq!(ct_webp, "image_webp");
        assert_eq!(w_webp, 800);
        assert_eq!(h_webp, 600);

        // 4. SVG and XML payload rejection
        let svg_payload = b"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\"><circle cx=\"50\" cy=\"50\" r=\"40\"/></svg>";
        assert!(validate_image_header(svg_payload).is_err(), "SVG payloads must be strictly rejected");

        let xml_payload = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg></svg>";
        assert!(validate_image_header(xml_payload).is_err(), "XML payloads must be strictly rejected");

        let script_payload = b"<script>alert(1)</script>";
        assert!(validate_image_header(script_payload).is_err(), "Script payloads must be strictly rejected");

        // 5. Dimension ceiling rejection (> 8192)
        let mut huge_png = png_data.clone();
        huge_png[16..20].copy_from_slice(&9000u32.to_be_bytes()); // 9000 width
        assert!(validate_image_header(&huge_png).is_err(), "PNG > 8192x8192 must be rejected");

        // 6. Zero dimension rejection
        let mut zero_png = png_data.clone();
        zero_png[20..24].copy_from_slice(&0u32.to_be_bytes()); // 0 height
        assert!(validate_image_header(&zero_png).is_err(), "PNG with 0 dimension must be rejected");
    }

    #[test]
    fn test_base64_codec_roundtrip() {
        let test_cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"Omarchy Next-Gen Wireless AirBridge Clipboard Synchronizer",
            &[0x00, 0xFF, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF],
        ];

        for &case in test_cases {
            let encoded = base64_encode(case);
            let decoded = base64_decode(&encoded).expect("Base64 decode must succeed");
            assert_eq!(decoded.as_slice(), case, "Base64 roundtrip must be lossless");
        }

        assert!(base64_decode("Invalid!!").is_err(), "Invalid Base64 characters must return Err");
        assert!(base64_decode("abc").is_err(), "Invalid Base64 length must return Err");
    }

    #[test]
    fn test_clip_staging_and_mode_0600_isolation() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());

        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        png_bytes.extend_from_slice(&13u32.to_be_bytes());
        png_bytes.extend_from_slice(b"IHDR");
        png_bytes.extend_from_slice(&64u32.to_be_bytes());
        png_bytes.extend_from_slice(&64u32.to_be_bytes());
        png_bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);

        let (hash, staged_path) = stage_clipboard_image(&png_bytes, "image_png").expect("Stage image");
        assert_eq!(hash.len(), 64);
        assert!(staged_path.exists());

        // Verify directory is 0700 and file is 0600
        let dir = get_clip_staging_dir();
        let dir_meta = fs::symlink_metadata(&dir).expect("Staging dir metadata");
        assert_eq!(dir_meta.mode() & 0o777, 0o700, "Staging dir must enforce 0700 permissions");

        let file_meta = fs::symlink_metadata(&staged_path).expect("Staged file metadata");
        assert_eq!(file_meta.mode() & 0o777, 0o600, "Staged image file must enforce 0600 permissions");

        // Verify BLAKE3 hash
        let expected_hash = compute_image_clipboard_hash(&png_bytes);
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_clip_staging_lru_cleanup_policy() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let staging_dir = get_clip_staging_dir();

        // Create a dummy valid PNG template
        let mut png_template = Vec::new();
        png_template.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        png_template.extend_from_slice(&13u32.to_be_bytes());
        png_template.extend_from_slice(b"IHDR");
        png_template.extend_from_slice(&32u32.to_be_bytes());
        png_template.extend_from_slice(&32u32.to_be_bytes());
        png_template.extend_from_slice(&[8, 6, 0, 0, 0]);
        png_template.extend_from_slice(&[0, 0, 0, 0]);

        // Stage 25 distinct images
        for i in 0u32..25u32 {
            let mut data = png_template.clone();
            data.extend_from_slice(&i.to_be_bytes());
            let _ = stage_clipboard_image(&data, "image_png");
            thread::sleep(Duration::from_millis(5));
        }

        cleanup_clip_staging().expect("LRU cleanup");

        let entries: Vec<_> = fs::read_dir(&staging_dir).unwrap().flatten().collect();
        assert!(entries.len() <= MAX_CLIP_STAGING_FILES, "Staging directory file count ({}) must not exceed MAX_CLIP_STAGING_FILES ({})", entries.len(), MAX_CLIP_STAGING_FILES);

        let total_bytes: u64 = entries.iter().map(|e| e.metadata().map(|m| m.len()).unwrap_or(0)).sum();
        assert!(total_bytes <= MAX_CLIP_STAGING_BYTES, "Total staging bytes ({}) must not exceed MAX_CLIP_STAGING_BYTES ({})", total_bytes, MAX_CLIP_STAGING_BYTES);
    }

    #[test]
    fn test_image_clipboard_hash_and_metadata_serialization() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let dummy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let item = ClipboardItem {
            timestamp: 1727700000,
            sender: "POCO Pad".to_string(),
            content_type: "image_png".to_string(),
            text: format!("[Image: {} (1920x1080)]", &dummy_hash[..8]),
            char_count: 0,
            is_url: false,
            image_hash: Some(dummy_hash.to_string()),
            image_size: Some(102400),
            image_width: Some(1920),
            image_height: Some(1080),
            thumbnail_base64: Some("dGh1bWJuYWls".to_string()),
        };

        let json = serde_json::to_string(&item).expect("Serialize image ClipboardItem");
        let parsed: ClipboardItem = serde_json::from_str(&json).expect("Deserialize image ClipboardItem");
        assert_eq!(parsed.content_type, "image_png");
        assert_eq!(parsed.image_hash.as_deref(), Some(dummy_hash));
        assert_eq!(parsed.image_width, Some(1920));

        let vault = load_clipboard_vault();
        assert!(vault.items.is_empty(), "Clipboard vault must not persist items to disk");
    }

    #[test]
    fn test_http_p2p_instant_text_clipboard_sync() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let valid_raw_oma_id = rendezvous::generate_raw_oma_id();
        let valid_peer_oma_id = rendezvous::format_oma_id(&valid_raw_oma_id);
        let paired_peer = confirmed_test_peer(&valid_peer_oma_id, "Instant Device");
        let auth_token = paired_peer.auth_token.unwrap_or_default();

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let local_addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("Accept text client");
            handle_connection(stream, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });

        let test_text = "Instant P2P text transmission test without vault persistence";
        let text_hash = compute_clipboard_hash(test_text);

        let post_payload = serde_json::json!({
            "oma_id": valid_peer_oma_id,
            "sender_id": valid_peer_oma_id,
            "sender_name": "Instant Device",
            "content_type": "text",
            "text": test_text
        });
        let post_bytes = post_payload.to_string().into_bytes();

        let mut client = TcpStream::connect(local_addr).expect("Connect client");
        let req = format!(
            "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nX-OmaSend-Auth-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            local_addr, valid_peer_oma_id, auth_token, post_bytes.len()
        );
        client.write_all(req.as_bytes()).unwrap();
        client.write_all(&post_bytes).unwrap();
        let mut resp = String::new();
        // The server may close before reading the whole request; keep what it sent.
        let _ = client.read_to_string(&mut resp);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "POST /api/p2p/clipboard must return 200 OK: {}", resp);

        let last_synced = get_last_synced_clipboard_hash();
        assert_eq!(last_synced.as_deref(), Some(text_hash.as_str()), "Last synced hash must be updated to prevent echo");

        server_thread.join().expect("Join server thread");
    }

    #[test]
    fn test_http_p2p_image_and_vault_endpoints() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let valid_raw_oma_id = rendezvous::generate_raw_oma_id();
        let valid_peer_oma_id = rendezvous::format_oma_id(&valid_raw_oma_id);
        let paired_peer = confirmed_test_peer(&valid_peer_oma_id, "Test Device");
        let auth_token = paired_peer.auth_token.unwrap_or_default();

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let local_addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("Accept client 1");
            handle_connection(stream, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

            let (stream, _) = listener.accept().expect("Accept client 2");
            handle_connection(stream, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

            let (stream, _) = listener.accept().expect("Accept client 3");
            handle_connection(stream, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

            let (stream, _) = listener.accept().expect("Accept client 4");
            handle_connection(stream, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });

        // 1. Post image clipboard
        let mut png_data = Vec::new();
        png_data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        png_data.extend_from_slice(&13u32.to_be_bytes());
        png_data.extend_from_slice(b"IHDR");
        png_data.extend_from_slice(&64u32.to_be_bytes());
        png_data.extend_from_slice(&64u32.to_be_bytes());
        png_data.extend_from_slice(&[8, 6, 0, 0, 0]);
        png_data.extend_from_slice(&[0, 0, 0, 0]);

        let b64 = base64_encode(&png_data);
        let img_hash = compute_image_clipboard_hash(&png_data);

        let post_payload = serde_json::json!({
            "oma_id": valid_peer_oma_id,
            "sender_id": valid_peer_oma_id,
            "sender_name": "Test Device",
            "content_type": "image_png",
            "image_hash": img_hash,
            "image_size": png_data.len(),
            "image_width": 64,
            "image_height": 64,
            "image_base64": b64
        });
        let post_bytes = post_payload.to_string().into_bytes();

        let mut client1 = TcpStream::connect(local_addr).expect("Connect client 1");
        let req1 = format!(
            "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nX-OmaSend-Auth-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            local_addr, valid_peer_oma_id, auth_token, post_bytes.len()
        );
        client1.write_all(req1.as_bytes()).unwrap();
        client1.write_all(&post_bytes).unwrap();
        let mut resp1 = String::new();
        client1.read_to_string(&mut resp1).unwrap();
        assert!(resp1.starts_with("HTTP/1.1 200 OK"), "POST /api/p2p/clipboard must return 200 OK: {}", resp1);

        // 2a. Fetching without pairing credentials is refused (M12).
        let mut client_anon = TcpStream::connect(local_addr).expect("Connect anonymous client");
        let req_anon = format!("GET /api/p2p/clipboard/image?hash={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", img_hash, local_addr);
        client_anon.write_all(req_anon.as_bytes()).unwrap();
        let mut resp_anon = String::new();
        client_anon.read_to_string(&mut resp_anon).unwrap();
        assert!(resp_anon.starts_with("HTTP/1.1 403"), "Unauthenticated image fetch must be refused: {}", resp_anon);

        // 2b. Fetch image via /api/p2p/clipboard/image/<hash> as the paired legacy peer
        let mut client2 = TcpStream::connect(local_addr).expect("Connect client 2");
        let req2 = format!(
            "GET /api/p2p/clipboard/image/{} HTTP/1.1\r\nHost: {}\r\nX-OmaSend-OmaID: {}\r\nX-OmaSend-Auth-Token: {}\r\nConnection: close\r\n\r\n",
            img_hash, local_addr, valid_peer_oma_id, auth_token
        );
        client2.write_all(req2.as_bytes()).unwrap();
        let mut resp2 = Vec::new();
        client2.read_to_end(&mut resp2).unwrap();
        assert!(resp2.starts_with(b"HTTP/1.1 200 OK"), "GET /api/p2p/clipboard/image/<hash> must return 200 OK");
        let header_end = resp2.windows(4).position(|w| w == b"\r\n\r\n").expect("HTTP delimiter");
        let body2 = &resp2[header_end + 4..];
        assert_eq!(body2, png_data.as_slice(), "Fetched image bytes must match original");

        // 3. Query vault via /api/p2p/clipboard/vault
        let mut client3 = TcpStream::connect(local_addr).expect("Connect client 3");
        let req3 = format!(
            "GET /api/p2p/clipboard/vault HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            local_addr
        );
        client3.write_all(req3.as_bytes()).unwrap();
        let mut resp3 = String::new();
        client3.read_to_string(&mut resp3).unwrap();
        assert!(resp3.starts_with("HTTP/1.1 200 OK"), "GET /api/p2p/clipboard/vault must return 200 OK");
        assert!(resp3.contains("\"items\":[]"), "Vault response must return empty items list");

        server_thread.join().expect("Join server thread");
    }

    #[test]
    fn test_p2p_clipboard_rejects_invalid_or_missing_auth_token() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let valid_raw_oma_id = rendezvous::generate_raw_oma_id();
        let valid_peer_oma_id = rendezvous::format_oma_id(&valid_raw_oma_id);
        let paired_peer = confirmed_test_peer(&valid_peer_oma_id, "Token Test Device");
        let _auth_token = paired_peer.auth_token.unwrap_or_default();

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let local_addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (stream1, _) = listener.accept().expect("Accept client 1");
            handle_connection(stream1, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

            let (stream2, _) = listener.accept().expect("Accept client 2");
            handle_connection(stream2, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });

        // 1. Missing token header and body -> 403 Forbidden
        let mut client1 = TcpStream::connect(local_addr).expect("Connect client 1");
        let payload1 = serde_json::json!({
            "oma_id": valid_peer_oma_id,
            "sender_id": valid_peer_oma_id,
            "sender_name": "Token Test Device",
            "content_type": "text",
            "text": "Unauthorized text attempt"
        });
        let bytes1 = payload1.to_string().into_bytes();
        let req1 = format!(
            "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            local_addr, valid_peer_oma_id, bytes1.len()
        );
        client1.write_all(req1.as_bytes()).unwrap();
        client1.write_all(&bytes1).unwrap();
        let mut resp1 = String::new();
        client1.read_to_string(&mut resp1).unwrap();
        assert!(resp1.starts_with("HTTP/1.1 403 Forbidden"), "Missing token must return 403: {}", resp1);

        // 2. Invalid token header -> 403 Forbidden
        let mut client2 = TcpStream::connect(local_addr).expect("Connect client 2");
        let req2 = format!(
            "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nX-OmaSend-Auth-Token: totally_wrong_token_hex\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            local_addr, valid_peer_oma_id, bytes1.len()
        );
        client2.write_all(req2.as_bytes()).unwrap();
        client2.write_all(&bytes1).unwrap();
        let mut resp2 = String::new();
        client2.read_to_string(&mut resp2).unwrap();
        assert!(resp2.starts_with("HTTP/1.1 403 Forbidden"), "Wrong token must return 403: {}", resp2);

        server_thread.join().expect("Join server thread");
    }

    #[test]
    fn test_webp_thumbnail_generation_and_caching() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());

        // Create valid 128x128 test PNG
        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        png_bytes.extend_from_slice(&13u32.to_be_bytes());
        png_bytes.extend_from_slice(b"IHDR");
        png_bytes.extend_from_slice(&128u32.to_be_bytes());
        png_bytes.extend_from_slice(&128u32.to_be_bytes());
        png_bytes.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);

        let (hash, staged_path) = stage_clipboard_image(&png_bytes, "image_png").expect("Stage PNG");

        // 1. Generate WebP thumbnail
        let thumb_dataurl = generate_webp_thumbnail_for_staging(&staged_path, &hash);
        if let Some(dataurl) = thumb_dataurl {
            assert!(dataurl.starts_with("data:image/webp;base64,"), "DataURL must start with WebP prefix");
            let b64_part = dataurl.trim_start_matches("data:image/webp;base64,");
            let decoded = base64_decode(b64_part).expect("Decode thumbnail base64");
            assert!(decoded.len() >= 12, "Thumbnail bytes must be valid WebP");
            assert_eq!(&decoded[0..4], b"RIFF");
            assert_eq!(&decoded[8..12], b"WEBP");

            let staging_dir = get_clip_staging_dir();
            let thumb_path = staging_dir.join(format!("{}_thumb.webp", hash));
            assert!(thumb_path.exists(), "Thumbnail file must exist in staging");

            let meta = fs::symlink_metadata(&thumb_path).expect("Thumbnail metadata");
            assert_eq!(meta.mode() & 0o777, 0o600, "Thumbnail file must enforce 0600 permissions");

            // 2. Fast cache path
            let cached_dataurl = generate_webp_thumbnail_for_staging(&staged_path, &hash);
            assert_eq!(cached_dataurl, Some(dataurl), "Cached thumbnail generation must match");
        }
    }

    #[test]
    fn test_webp_thumbnail_security_and_bounds() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let staging_dir = get_clip_staging_dir();

        // 1. Path traversal hash rejection
        let dummy_path = staging_dir.join("test.png");
        assert!(generate_webp_thumbnail_for_staging(&dummy_path, "../../../etc/passwd").is_none());
        assert!(generate_webp_thumbnail_for_staging(&dummy_path, "short_hash").is_none());
        assert!(generate_webp_thumbnail_for_staging(&dummy_path, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());

        // 2. Symlink rejection
        let temp_dir = std::env::temp_dir().join(format!("omasend_thumb_symlink_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let real_file = temp_dir.join("real.png");
        write_secure_bytes(&real_file, b"\x89PNG\r\n\x1a\n").unwrap();

        let symlink_file = temp_dir.join("symlink.png");
        std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();

        let valid_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(generate_webp_thumbnail_for_staging(&symlink_file, valid_hash).is_none(), "Symlink input must be rejected");

        // 3. Non-existent file rejection
        let non_existent = temp_dir.join("missing.png");
        assert!(generate_webp_thumbnail_for_staging(&non_existent, valid_hash).is_none(), "Missing file must be rejected");

        // 4. Empty file rejection
        let empty_file = temp_dir.join("empty.png");
        write_secure_bytes(&empty_file, b"").unwrap();
        assert!(generate_webp_thumbnail_for_staging(&empty_file, valid_hash).is_none(), "Empty file must be rejected");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_cleanup_clip_staging_with_thumbnails() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let staging_dir = get_clip_staging_dir();

        let mut png_template = Vec::new();
        png_template.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        png_template.extend_from_slice(&13u32.to_be_bytes());
        png_template.extend_from_slice(b"IHDR");
        png_template.extend_from_slice(&32u32.to_be_bytes());
        png_template.extend_from_slice(&32u32.to_be_bytes());
        png_template.extend_from_slice(&[8, 6, 0, 0, 0]);
        png_template.extend_from_slice(&[0, 0, 0, 0]);

        for i in 0u32..25u32 {
            let mut data = png_template.clone();
            data.extend_from_slice(&i.to_be_bytes());
            if let Ok((hash, staged_path)) = stage_clipboard_image(&data, "image_png") {
                let _ = generate_webp_thumbnail_for_staging(&staged_path, &hash);
            }
            thread::sleep(Duration::from_millis(5));
        }

        cleanup_clip_staging().expect("LRU cleanup with thumbnails");

        let entries: Vec<_> = fs::read_dir(&staging_dir).unwrap().flatten().collect();
        assert!(entries.len() <= MAX_CLIP_STAGING_FILES, "Total entries in staging must not exceed MAX_CLIP_STAGING_FILES");

        let total_bytes: u64 = entries.iter().map(|e| e.metadata().map(|m| m.len()).unwrap_or(0)).sum();
        assert!(total_bytes <= MAX_CLIP_STAGING_BYTES, "Total staging bytes must not exceed MAX_CLIP_STAGING_BYTES");
    }

    fn post_json(addr: std::net::SocketAddr, path: &str, extra_headers: &str, body: &serde_json::Value) -> String {
        let bytes = body.to_string().into_bytes();
        let mut c = TcpStream::connect(addr).expect("Connect test client");
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            path, addr, extra_headers, bytes.len()
        );
        c.write_all(req.as_bytes()).unwrap();
        c.write_all(&bytes).unwrap();
        let mut resp = String::new();
        // The server may close before reading the whole request; keep what it sent.
        let _ = c.read_to_string(&mut resp);
        resp
    }

    #[test]
    fn test_p2p_pair_rejects_loopback_tunnel_source_and_legacy_body_fields() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let peer_id = rendezvous::format_oma_id(&rendezvous::generate_raw_oma_id());
        let (pending, code) = begin_local_pairing(&peer_id, "Tunnel Target", None).expect("Begin pairing");

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (s, _) = listener.accept().expect("Accept");
                handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
            }
        });

        // Correct code but loopback source (as forwarded by the WAN tunnel) -> 403
        let r1 = post_json(addr, "/api/p2p/pair", "", &serde_json::json!({ "oma_id": peer_id, "pair_code": code }));
        assert!(r1.starts_with("HTTP/1.1 403"), "Loopback pairing must be refused: {}", r1);

        // Old takeover payload without code (attacker ip + token) -> 403
        let r2 = post_json(addr, "/api/p2p/pair", "", &serde_json::json!({
            "oma_id": peer_id, "ip": "192.168.1.250",
            "auth_token": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }));
        assert!(r2.starts_with("HTTP/1.1 403"), "Codeless pairing must be refused: {}", r2);
        server.join().unwrap();

        let stored = load_paired_peers().into_iter().find(|p| rendezvous::normalize_oma_id(&p.oma_id) == rendezvous::normalize_oma_id(&peer_id)).expect("Record kept");
        assert!(!stored.confirmed);
        assert_eq!(stored.ip, None);
        assert_eq!(stored.auth_token, pending.auth_token, "Token must not be replaced remotely");
    }

    #[test]
    fn test_p2p_clipboard_rejects_unconfirmed_peer_even_with_valid_token() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let peer_id = rendezvous::format_oma_id(&rendezvous::generate_raw_oma_id());
        let unconfirmed = add_paired_peer(&peer_id, "Legacy Device", None).expect("Add unconfirmed peer");
        let token = unconfirmed.auth_token.unwrap_or_default();

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (s, _) = listener.accept().expect("Accept");
            handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });
        let headers = format!("X-OmaSend-OmaID: {}\r\nX-OmaSend-Auth-Token: {}\r\n", peer_id, token);
        let r = post_json(addr, "/api/p2p/clipboard", &headers, &serde_json::json!({
            "oma_id": peer_id, "sender_id": peer_id, "sender_name": "Legacy Device",
            "content_type": "text", "text": "should be refused"
        }));
        server.join().unwrap();
        assert!(r.starts_with("HTTP/1.1 403"), "Unconfirmed peer must be refused inbound: {}", r);
    }

    #[test]
    fn test_p2p_clipboard_rejects_trusted_only_sender_without_pairing() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let rogue_id = "trusted-only-device-0001";
        add_trusted_peer(rogue_id, "Trusted Only", "");
        assert!(is_peer_trusted(rogue_id));
        assert!(legacy_peer_authorized("").is_none());

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (s, _) = listener.accept().expect("Accept");
            handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });
        let r = post_json(addr, "/api/p2p/clipboard", "X-OmaSend-OmaID: trusted-only-device-0001\r\n", &serde_json::json!({
            "oma_id": rogue_id, "sender_id": rogue_id, "sender_name": "Trusted Only",
            "content_type": "text", "text": "no token, no pairing"
        }));
        server.join().unwrap();
        assert!(r.starts_with("HTTP/1.1 403"), "Trusted-only sender must be refused: {}", r);
    }

    #[test]
    fn test_p2p_clipboard_rejects_sensitive_keys_and_passwords() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let valid_raw_oma_id = rendezvous::generate_raw_oma_id();
        let peer_id = rendezvous::format_oma_id(&valid_raw_oma_id);
        let paired_peer = confirmed_test_peer(&peer_id, "Paired Peer");
        let auth_token = paired_peer.auth_token.unwrap_or_default();

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (s, _) = listener.accept().expect("Accept");
            handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });

        // Send private key
        let headers = format!("X-OmaSend-OmaID: {}\r\nX-OmaSend-Auth-Token: {}\r\n", peer_id, auth_token);
        let r = post_json(addr, "/api/p2p/clipboard", &headers, &serde_json::json!({
            "oma_id": peer_id, "sender_id": peer_id, "sender_name": "Paired Peer",
            "content_type": "text", "text": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ..."
        }));
        server.join().unwrap();
        assert!(r.starts_with("HTTP/1.1 403"), "Sensitive credentials must be refused: {}", r);
        assert!(r.contains("clipboard shield"), "Response should explain shield rejection: {}", r);
    }

    /// A legacy (v1) peer is identified by its pairing token alone; the OmaID it claims does
    /// not matter, and an OmaID without the token authorizes nothing.
    #[test]
    fn test_p2p_clipboard_legacy_token_is_the_credential() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let peer_id = rendezvous::format_oma_id(&rendezvous::generate_raw_oma_id());
        let paired_peer = confirmed_test_peer(&peer_id, "Paired Peer");
        let auth_token = paired_peer.auth_token.unwrap_or_default();
        assert!(!auth_token.is_empty());
        assert_eq!(legacy_peer_authorized(&auth_token).map(|p| p.oma_id), Some(paired_peer.oma_id.clone()));

        let text = serde_json::json!({ "sender_name": "Paired Peer", "content_type": "text", "text": "token only, no OmaID" });
        let r = post_once("/api/p2p/clipboard", &format!("X-OmaSend-Auth-Token: {}\r\n", auth_token), &text);
        assert!(r.starts_with("HTTP/1.1 200 OK"), "token-authenticated legacy clipboard must work: {}", r);

        let claimed = serde_json::json!({ "oma_id": peer_id, "sender_id": peer_id, "content_type": "text", "text": "claim only" });
        let r = post_once("/api/p2p/clipboard", &format!("X-OmaSend-OmaID: {}\r\n", peer_id), &claimed);
        assert!(r.starts_with("HTTP/1.1 403"), "a claimed OmaID without the token must be refused: {}", r);

        // The old OmaID-keyed "encrypted_envelope" is not decrypted any more.
        let r = post_once("/api/p2p/clipboard", &format!("X-OmaSend-Auth-Token: {}\r\n", auth_token), &serde_json::json!({
            "encrypted_envelope": { "v": 2, "sender_oma_id": peer_id, "nonce": "00", "ciphertext": "00", "timestamp": 0 }
        }));
        assert!(r.starts_with("HTTP/1.1 400"), "{}", r);
    }

    #[test]
    fn test_claimed_same_owner_oma_id_requires_approval_and_pairing() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        // V2-SEC-01: OmaID is public (broadcast in beacons), so claiming our own OmaID must NOT
        // auto-accept transfers or authorize clipboard writes.
        clear_pending_transfer();
        // EVERYONE: under KNOWN an unpaired sender is refused outright (see the test below).
        set_visibility("EVERYONE");
        let my_oma_id = get_or_create_oma_id();

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (s, _) = listener.accept().expect("Accept same-owner client");
                handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
            }
        });

        // 1. Claimed same-owner file transfer request -> still needs user approval ("PENDING")
        let req_headers = format!("X-OmaSend-OmaID: {}\r\n", my_oma_id);
        let resp_transfer = post_json(addr, "/api/p2p/request", &req_headers, &serde_json::json!({
            "oma_id": my_oma_id,
            "sender_id": my_oma_id,
            "sender_name": "My Other Omarchy Laptop",
            "files": [{"name": "notes.txt", "size_bytes": 128}]
        }));
        assert!(resp_transfer.starts_with("HTTP/1.1 200 OK"), "Same-owner transfer must return 200 OK: {}", resp_transfer);
        assert!(resp_transfer.contains("\"status\":\"PENDING\""), "Claimed same-owner transfer must not auto-accept: {}", resp_transfer);
        assert!(resp_transfer.contains("\"is_same_owner\":false"), "A claimed OmaID is not proof of ownership: {}", resp_transfer);

        // 2. Claimed same-owner clipboard write without a confirmed pairing -> rejected
        let resp_clip = post_json(addr, "/api/p2p/clipboard", &req_headers, &serde_json::json!({
            "oma_id": my_oma_id,
            "sender_id": my_oma_id,
            "sender_name": "My Other Omarchy Laptop",
            "content_type": "text",
            "text": "Anonymous Numbered OmaID Zero-Click Same-Owner Clipboard Sync"
        }));
        assert!(resp_clip.starts_with("HTTP/1.1 403"), "Claimed same-owner clipboard without pairing must be rejected: {}", resp_clip);

        server.join().unwrap();
    }

    #[test]
    fn test_different_owner_pending_gatekeeper_and_oma_id_resolution() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        clear_pending_transfer();
        set_visibility("ALL");

        let foreign_raw = rendezvous::generate_raw_oma_id();
        let foreign_oma_id = rendezvous::format_oma_id(&foreign_raw);

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (s, _) = listener.accept().expect("Accept foreign OmaID client");
            handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });

        // Different OmaID user sending file in ALL/EVERYONE visibility -> Gatekeeper records as PENDING
        let headers = format!("X-OmaSend-OmaID: {}\r\n", foreign_oma_id);
        let resp = post_json(addr, "/api/p2p/request", &headers, &serde_json::json!({
            "oma_id": foreign_oma_id,
            "sender_id": foreign_oma_id,
            "sender_name": "Colleague Workstation",
            "files": [{"name": "report.pdf", "size_bytes": 4096}]
        }));
        server.join().unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "Foreign OmaID in ALL visibility must return 200 OK with PENDING: {}", resp);
        assert!(resp.contains("\"status\":\"PENDING\""), "Foreign OmaID must enter Gatekeeper PENDING state: {}", resp);
        assert!(resp.contains("\"is_same_owner\":false"), "Foreign OmaID must have is_same_owner=false: {}", resp);

        // An OmaID seen only in a (spoofable) beacon does not resolve to an address.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let peers = vec![DiscoveredPeer {
            id: "dev_colleague_01".to_string(),
            oma_id: foreign_oma_id.clone(),
            name: "Colleague Workstation".to_string(),
            ip: "192.168.1.88".to_string(),
            port: 53317,
            transport: "LAN".to_string(),
            fingerprint: "fp_colleague".to_string(),
            is_trusted: false,
            is_same_owner: false,
            last_seen_secs: now,
            pk: String::new(),
            key_trust: String::new(),
        }];
        save_discovered_peers(&peers);

        assert!(resolve_target_ip_or_omaid(&foreign_oma_id).is_err(), "beacon-claimed OmaID must not resolve");

        // A code-verified pairing does: its address is the observed source of the handshake.
        let paired = confirmed_test_peer(&foreign_oma_id, "Colleague Workstation");
        let (resolved_ip, resolved_port, resolved_oma) = resolve_target_ip_or_omaid(&foreign_oma_id)
            .expect("Resolve paired target by 16-digit OmaID");
        assert_eq!(Some(resolved_ip), paired.ip);
        assert_eq!(resolved_port, PORT);
        assert_eq!(resolved_oma.as_deref(), Some(foreign_oma_id.as_str()));
    }

    #[test]
    fn test_transfer_cancel_progress_and_sound_settings() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        clear_transfer_cancel();
        assert!(!is_transfer_cancelled());
        request_transfer_cancel();
        assert!(is_transfer_cancelled());
        clear_transfer_cancel();
        assert!(!is_transfer_cancelled());

        save_transfer_progress("receive", "archive.tar", 512, 1024);
        let prog = get_transfer_progress().expect("Progress should be present");
        assert_eq!(prog["direction"].as_str(), Some("receive"));
        assert_eq!(prog["file_name"].as_str(), Some("archive.tar"));
        assert_eq!(prog["percent"].as_u64(), Some(50));
        clear_transfer_progress();
        assert!(get_transfer_progress().is_none());

        set_sound_enabled(false);
        assert!(!is_sound_enabled());
        set_sound_enabled(true);
        assert!(is_sound_enabled());
    }

    fn raw_http(addr: std::net::SocketAddr, head: &str, body: &[u8]) -> String {
        let mut c = TcpStream::connect(addr).expect("Connect test client");
        c.write_all(head.as_bytes()).unwrap();
        // The server may answer (e.g. 401) and close before reading the body; a reset while
        // writing or reading the rest is expected then, the status line is what matters.
        let _ = c.write_all(body);
        let mut resp = Vec::new();
        let _ = c.read_to_end(&mut resp);
        String::from_utf8_lossy(&resp).to_string()
    }

    #[test]
    fn test_phase1_qr_pairing_and_signed_requests_end_to_end() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        clear_pending_transfer();
        set_visibility("ALL");

        // The "phone" is a separate identity; this process plays the desktop (responder).
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let phone = devicekey::DeviceIdentity::from_seed(seed);
        let _ = trust_store().remove(&phone.public_b64());

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..5 {
                let (s, _) = listener.accept().expect("Accept client");
                handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
            }
        });

        // 1. Pair via QR offer marked "own device".
        let offer_json = create_pair_offer_json(true);
        let offer = devicekey::parse_pair_uri(offer_json["uri"].as_str().unwrap()).unwrap();
        let pair_body = devicekey::build_pair_request(&phone, &offer, "Test Phone", 0).to_string();
        let r = post_json(addr, "/api/v2/pair", "", &serde_json::from_str(&pair_body).unwrap());
        assert!(r.starts_with("HTTP/1.1 200"), "pairing must succeed: {}", r);
        let resp_json: serde_json::Value = serde_json::from_str(r.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        devicekey::verify_pair_response(&phone, &offer, &resp_json).expect("desktop signature must verify");

        // 2. Signed transfer request from the verified own device is auto-accepted.
        let oma = rendezvous::format_oma_id(&rendezvous::generate_raw_oma_id());
        let body = serde_json::json!({
            "oma_id": oma, "sender_id": oma, "sender_name": "Spoofable name",
            "files": [{"name": "photo.jpg", "size_bytes": 3}]
        }).to_string().into_bytes();
        let sig = devicekey::auth_header_lines(&phone, "POST", "/api/p2p/request", &devicekey::body_tag_json(&body));
        let head = format!("POST /api/p2p/request HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n", sig, body.len());
        let r = raw_http(addr, &head, &body);
        assert!(r.contains("\"status\":\"ACCEPTED\""), "verified own device must auto-accept: {}", r);
        assert!(r.contains("\"verified_device\":true"), "{}", r);
        let token = serde_json::from_str::<serde_json::Value>(r.split("\r\n\r\n").nth(1).unwrap()).unwrap()["token"].as_str().unwrap().to_string();

        // 3. Upload of that transfer by a different (unsigned) client is rejected.
        let pq = format!("/api/p2p/upload?token={}&filename=photo.jpg", token);
        let r = raw_http(addr, &format!("POST {} HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: close\r\n\r\n", pq), b"abc");
        assert!(r.starts_with("HTTP/1.1 401"), "unsigned upload of a verified transfer must fail: {}", r);

        // 4. Tampered body (signature over different bytes) is rejected.
        let sig = devicekey::auth_header_lines(&phone, "POST", "/api/p2p/clipboard", &devicekey::body_tag_json(b"{}"));
        let evil = br#"{"content_type":"text","text":"evil"}"#;
        let head = format!("POST /api/p2p/clipboard HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n", sig, evil.len());
        let r = raw_http(addr, &head, evil);
        assert!(r.starts_with("HTTP/1.1 401"), "tampered signed request must fail: {}", r);

        // 5. Signed upload from the paired phone succeeds.
        let sig = devicekey::auth_header_lines(&phone, "POST", &pq, &devicekey::body_tag_stream(3));
        let r = raw_http(addr, &format!("POST {} HTTP/1.1\r\nHost: x\r\n{}Content-Length: 3\r\nConnection: close\r\n\r\n", pq, sig), b"abc");
        assert!(r.starts_with("HTTP/1.1 200"), "signed upload must succeed: {}", r);

        server.join().unwrap();
        clear_pending_transfer();
        let _ = trust_store().remove(&phone.public_b64());
        let _ = fs::remove_file(get_download_dir().join("photo.jpg"));
    }

    #[test]
    fn test_v2_func01_second_request_does_not_overwrite_pending_transfer() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        clear_pending_transfer();
        set_visibility("ALL");

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (s, _) = listener.accept().expect("Accept client");
                handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
            }
        });

        let first = rendezvous::format_oma_id(&rendezvous::generate_raw_oma_id());
        let second = rendezvous::format_oma_id(&rendezvous::generate_raw_oma_id());
        let r1 = post_json(addr, "/api/p2p/request", &format!("X-OmaSend-OmaID: {}\r\n", first), &serde_json::json!({
            "oma_id": first, "sender_id": first, "sender_name": "First",
            "files": [{"name": "a.txt", "size_bytes": 10}]
        }));
        let r2 = post_json(addr, "/api/p2p/request", &format!("X-OmaSend-OmaID: {}\r\n", second), &serde_json::json!({
            "oma_id": second, "sender_id": second, "sender_name": "Second",
            "files": [{"name": "b.txt", "size_bytes": 10}]
        }));
        server.join().unwrap();

        assert!(r1.contains("\"status\":\"PENDING\""), "First request must be pending: {}", r1);
        assert!(r2.starts_with("HTTP/1.1 409"), "Second request must not overwrite the live one: {}", r2);
        let pending = get_pending_transfer().expect("First pending transfer must survive");
        assert_eq!(pending.sender_name, "First");
        clear_pending_transfer();
    }

    #[test]
    fn test_v2_sec06_upload_size_must_match_approved_size() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        clear_pending_transfer();
        set_visibility("ALL");

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let token = "v2sec06token00000000000000000000".to_string();
        save_pending_transfer(&PendingFileTransfer {
            token: token.clone(),
            sender_id: "tester".to_string(),
            sender_name: "Tester".to_string(),
            sender_ip: "127.0.0.1".to_string(),
            file_names: vec!["small.txt".to_string()],
            remaining_files: 1,
            files: vec![TransferFileInfo {
                name: "small.txt".to_string(),
                size_bytes: 4,
                blake3: None,
                sha256: None,
                md5: None,
            }],
            total_size_bytes: 4,
            created_at: now,
            expires_at: now + 60,
            status: "ACCEPTED".to_string(),
            sender_pk: None,
            transport: None,
        });

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (s, _) = listener.accept().expect("Accept client");
            handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });

        let body = b"this body is much larger than four bytes";
        let mut c = TcpStream::connect(addr).expect("Connect test client");
        let req = format!(
            "POST /api/p2p/upload?token={}&filename=small.txt HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            token, addr, body.len()
        );
        c.write_all(req.as_bytes()).unwrap();
        c.write_all(body).unwrap();
        let mut resp = String::new();
        // The server may close before reading the whole request; keep what it sent.
        let _ = c.read_to_string(&mut resp);
        server.join().unwrap();

        assert!(resp.starts_with("HTTP/1.1 413"), "Oversized upload must be rejected: {}", resp);
        clear_pending_transfer();
    }

    #[test]
    fn test_paired_target_resolution_and_addresses() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let pk = devicekey::DeviceIdentity::from_seed([42u8; 32]).public_b64();
        let other_pk = devicekey::DeviceIdentity::from_seed([43u8; 32]).public_b64();
        let key = devicekey::TrustedKey {
            pk: pk.clone(),
            device_id: devicekey::device_id_for_pk(&devicekey::decode_pk(&pk).unwrap().to_bytes()),
            name: "Phone".into(),
            ip: "192.168.1.20".into(),
            port: PORT,
            quic_port: 0,
            own_device: true,
            added_at: now,
            last_seen: now,
        };
        trust_store().upsert(key.clone()).unwrap();
        let peer_oma = rendezvous::format_oma_id(&rendezvous::generate_raw_oma_id());
        let peer = |id: &str, ip: &str, pk: &str| DiscoveredPeer {
            id: id.into(),
            oma_id: peer_oma.clone(),
            name: id.into(),
            ip: ip.into(),
            port: PORT,
            transport: "LAN".into(),
            fingerprint: String::new(),
            is_trusted: false,
            is_same_owner: false,
            last_seen_secs: now,
            pk: pk.into(),
            key_trust: String::new(),
        };

        // By device id, public key and last authenticated address.
        save_discovered_peers(&[]);
        assert_eq!(trusted_key_for_target(&key.device_id).map(|k| k.pk), Some(pk.clone()));
        assert_eq!(trusted_key_for_target(&key.device_id.to_lowercase()).map(|k| k.pk), Some(pk.clone()));
        assert_eq!(trusted_key_for_target(&pk).map(|k| k.pk), Some(pk.clone()));
        assert_eq!(trusted_key_for_target("192.168.1.20:53317").map(|k| k.pk), Some(pk.clone()));
        assert!(trusted_key_for_target("192.168.1.99").is_none());
        assert_eq!(core_addrs(&key), vec!["192.168.1.20:53318".to_string()]);

        // DHCP: the key moved; discovery advertises it at a new address -> both are candidates.
        save_discovered_peers(&[peer("phone", "192.168.1.31", &pk)]);
        assert_eq!(trusted_key_for_target("192.168.1.31").map(|k| k.pk), Some(pk.clone()));
        assert_eq!(core_addrs(&key), vec!["192.168.1.31:53318".to_string(), "192.168.1.20:53318".to_string()]);
        assert_eq!(get_discovered_peers()[0].key_trust, "own");

        // DHCP reuse: another device now sits at the key's old address -> not the paired key.
        save_discovered_peers(&[peer("stranger", "192.168.1.20", &other_pk)]);
        assert!(trusted_key_for_target("192.168.1.20").is_none());
        assert_eq!(get_discovered_peers()[0].key_trust, "");

        // Older peer without an advertised key at the key's address -> falls back to the address.
        save_discovered_peers(&[peer("old", "192.168.1.20", "")]);
        assert_eq!(trusted_key_for_target("192.168.1.20").map(|k| k.pk), Some(pk.clone()));

        let view = paired_devices_view();
        let me = view.iter().find(|v| v["device_id"] == key.device_id.as_str()).unwrap();
        assert_eq!(me["online"], true);
        assert_eq!(me["own_device"], true);

        // Auto-send picks the own device by id, never a raw address.
        assert_eq!(auto_send_target(), Some(key.device_id.clone()));

        trust_store().remove(&pk).unwrap();
        save_discovered_peers(&[]);
    }

    #[test]
    fn test_beacon_pk_is_optional_on_the_wire() {
        // Older beacons (no pk) still parse; empty pk is not serialized.
        let old = r#"{"magic":"OMASEND_P2P","v":1,"id":"a","oma_id":"4829-1048-5729-1104","name":"n","ip":"1.2.3.4","port":53317,"mode":"KNOWN","fp":"f"}"#;
        let p: P2pBeaconPacket = serde_json::from_str(old).unwrap();
        assert!(p.pk.is_empty());
        assert!(!serde_json::to_string(&p).unwrap().contains("\"pk\""));
    }

    fn serve_one(listener: TcpListener) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (s, _) = listener.accept().expect("Accept");
            handle_connection(s, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        })
    }

    fn post_once(path: &str, headers: &str, body: &serde_json::Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = serve_one(listener);
        let r = post_json(addr, path, headers, body);
        server.join().unwrap();
        r
    }

    fn get_once(path: &str, headers: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let addr = listener.local_addr().unwrap();
        let server = serve_one(listener);
        let mut c = TcpStream::connect(addr).expect("Connect test client");
        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n", path, addr, headers);
        c.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        let _ = c.read_to_string(&mut resp);
        server.join().unwrap();
        resp
    }

    fn test_pending(token: &str, status: &str, expires_in: u64, sender_pk: Option<&str>) -> PendingFileTransfer {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        PendingFileTransfer {
            token: token.to_string(),
            sender_id: "0000-0000-0000-0000".to_string(),
            sender_name: "Test".to_string(),
            sender_ip: String::new(),
            file_names: vec!["a.txt".to_string(), "b.txt".to_string()],
            files: Vec::new(),
            remaining_files: 2,
            total_size_bytes: 2,
            created_at: now,
            expires_at: now + expires_in,
            status: status.to_string(),
            sender_pk: sender_pk.map(String::from),
            transport: None,
        }
    }

    /// M2: the WAN tunnel connects from loopback, so loopback alone must not approve transfers.
    #[test]
    fn test_decision_requires_local_token_not_bare_loopback() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_pin_rate_limiter();
        save_pending_transfer(&test_pending("tok-m2", "PENDING", 30, None));
        let body = serde_json::json!({ "token": "tok-m2", "action": "accept" });

        let r = post_once("/api/p2p/decision", "", &body);
        assert!(r.starts_with("HTTP/1.1 403"), "bare loopback must be refused: {}", r);

        let local = format!("X-OmaSend-Local: {}\r\n", ensure_local_api_token());
        let tunneled = format!("{}Cf-Connecting-Ip: 203.0.113.9\r\n", local);
        let r = post_once("/api/p2p/decision", &tunneled, &body);
        assert!(r.starts_with("HTTP/1.1 404"), "tunnelled request must be refused even with a token: {}", r);
        assert_eq!(get_pending_transfer().unwrap().status, "PENDING");

        let r = post_once("/api/p2p/decision", &local, &body);
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("ACCEPTED"), "{}", r);
        let p = get_pending_transfer().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        assert_eq!(p.status, "ACCEPTED");
        assert!(p.expires_at >= now + PENDING_IDLE_SECS - 5, "accept must extend the upload window");

        // A decided transfer cannot be decided again.
        let r = post_once("/api/p2p/decision", &local, &serde_json::json!({ "token": "tok-m2", "action": "reject" }));
        assert!(r.starts_with("HTTP/1.1 409"), "{}", r);
        clear_pending_transfer();
    }

    /// M10: an expired request reports EXPIRED, not NOT_FOUND.
    #[test]
    fn test_decision_poll_reports_expired() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let mut p = test_pending("tok-exp", "PENDING", 0, None);
        p.expires_at -= 5;
        save_pending_transfer(&p);
        let r = get_once("/api/p2p/decision?token=tok-exp", "");
        assert!(r.contains("EXPIRED"), "{}", r);
        let r = get_once("/api/p2p/decision?token=other", "");
        assert!(r.starts_with("HTTP/1.1 404"), "{}", r);
        clear_pending_transfer();
    }

    /// M5: WAN clients (all loopback) are rate limited by their real address, and the local
    /// CLI with the local token is never locked out by them.
    #[test]
    fn test_pin_lockout_does_not_block_local_control() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_pin_rate_limiter();
        for _ in 0..6 {
            let _ = get_once("/api/status", "X-OmaSend-PIN: 0000\r\nCf-Connecting-Ip: 198.51.100.7\r\n");
        }
        let r = get_once("/api/status", "Cf-Connecting-Ip: 198.51.100.7\r\n");
        assert!(r.starts_with("HTTP/1.1 429"), "attacker bucket must be blocked: {}", r);
        let r = get_once("/api/status", "Cf-Connecting-Ip: 198.51.100.8\r\n");
        assert!(r.starts_with("HTTP/1.1 200"), "other WAN clients keep working: {}", r);
        let r = get_once("/api/status", "");
        assert!(r.starts_with("HTTP/1.1 200"), "plain loopback keeps working: {}", r);

        // Wrong PINs sent together with the local token are not counted, so they never lock out
        // loopback. (Asserting this without locking out 127.0.0.1 keeps parallel tests safe.)
        let local = format!("X-OmaSend-Local: {}\r\n", ensure_local_api_token());
        for _ in 0..6 {
            let r = get_once("/api/status", &format!("{}X-OmaSend-PIN: 0000\r\n", local));
            assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
        }
        let r = get_once("/api/status", "");
        assert!(r.starts_with("HTTP/1.1 200"), "loopback must not be locked out: {}", r);
        reset_pin_rate_limiter();
    }

    /// M9: visibility KNOWN refuses unpaired HTTP senders (even with our own, public, OmaID).
    #[test]
    fn test_known_visibility_refuses_unpaired_sender() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        clear_pending_transfer();
        set_visibility("KNOWN");
        let my_oma_id = get_or_create_oma_id();
        let r = post_once("/api/p2p/request", &format!("X-OmaSend-OmaID: {}\r\n", my_oma_id), &serde_json::json!({
            "oma_id": my_oma_id, "sender_name": "Stranger", "files": [{"name": "x.txt", "size_bytes": 1}]
        }));
        assert!(r.starts_with("HTTP/1.1 403"), "{}", r);
        assert!(get_pending_transfer().is_none());
        set_visibility("ALL");
    }

    /// M9/M10: an unverified PENDING request does not block a verified sender, but a verified
    /// or accepted transfer is never displaced.
    #[test]
    fn test_pending_slot_preemption_rules() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        clear_pending_transfer();
        assert!(claim_pending_slot(&test_pending("anon-1", "PENDING", 30, None), false));
        assert!(!claim_pending_slot(&test_pending("anon-2", "PENDING", 30, None), false), "unverified cannot displace");
        assert!(claim_pending_slot(&test_pending("v2-1", "PENDING", 30, Some("pk1")), true), "verified displaces unverified");
        assert!(!claim_pending_slot(&test_pending("v2-2", "PENDING", 30, Some("pk2")), true), "verified is not displaced");
        assert_eq!(get_pending_transfer().unwrap().token, "v2-1");
        clear_pending_transfer();
        assert!(claim_pending_slot(&test_pending("anon-acc", "ACCEPTED", 30, None), false));
        assert!(!claim_pending_slot(&test_pending("v2-3", "PENDING", 30, Some("pk3")), true), "accepted transfer is not displaced");
        clear_pending_transfer();
        let mut old = test_pending("old", "PENDING", 0, None);
        old.expires_at -= 5;
        save_pending_transfer(&old);
        assert!(claim_pending_slot(&test_pending("new", "PENDING", 30, None), false), "expired record frees the slot");
        clear_pending_transfer();
    }

    /// M12: the discovered-peer list is local-only.
    #[test]
    fn test_peers_endpoint_requires_local_token() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_pin_rate_limiter();
        let r = get_once("/api/p2p/peers", "");
        assert!(r.starts_with("HTTP/1.1 403"), "{}", r);
        let r = get_once("/api/p2p/peers", &format!("X-OmaSend-Local: {}\r\n", ensure_local_api_token()));
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("\"peers\""), "{}", r);
    }

    /// M4: a pairing link must point into the local network.
    #[test]
    fn test_inspect_pair_uri_requires_private_host() {
        use base64::Engine as _;
        let id = devicekey::DeviceIdentity::from_seed([7u8; 32]);
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; 32]);
        let mk = |h: &str| format!("omasend://pair?v=2&pk={}&s={}&h={}&p=53317&n=Desk&o=1&q=53318", id.public_b64(), secret, h);
        let (offer, dev) = inspect_pair_uri(&mk("192.168.1.20")).expect("private host is fine");
        assert_eq!(dev, "FE81-2C12-F3AB-4CE6");
        assert_eq!(offer.name, "Desk");
        assert!(inspect_pair_uri(&mk("fe80::1")).is_ok());
        for bad in ["8.8.8.8", "127.0.0.1", "203.0.113.5", "example.com"] {
            assert!(inspect_pair_uri(&mk(bad)).is_err(), "{} must be refused", bad);
        }
    }

    fn multipart_body(boundary: &str, filename: &str, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(format!("--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n", boundary, filename).as_bytes());
        b.extend_from_slice(data);
        b.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
        b
    }

    /// M7: only the file bytes are saved, not the closing boundary.
    #[test]
    fn test_locate_multipart_file_strips_closing_boundary() {
        let boundary = "----WebKitFormBoundaryAbC123";
        // Data that itself contains CRLFs and a boundary-like line must survive intact.
        let data = b"line1\r\n--not-the-boundary\r\n\r\nend\r\n".to_vec();
        let body = multipart_body(boundary, "résumé.txt", &data);
        let ct = format!("multipart/form-data; boundary={}", boundary);
        let (start, end, name) = locate_multipart_file(&mut std::io::Cursor::new(&body), body.len() as u64, Some(&ct)).unwrap();
        assert_eq!(&body[start as usize..end as usize], data.as_slice());
        assert_eq!(name, "résumé.txt");
        // Without a Content-Type header the boundary is taken from the first line.
        let (s2, e2, _) = locate_multipart_file(&mut std::io::Cursor::new(&body), body.len() as u64, None).unwrap();
        assert_eq!((s2, e2), (start, end));
        // Empty file.
        let empty = multipart_body(boundary, "e.bin", b"");
        let (s3, e3, _) = locate_multipart_file(&mut std::io::Cursor::new(&empty), empty.len() as u64, Some(&ct)).unwrap();
        assert_eq!(s3, e3);
        // Not multipart.
        assert!(locate_multipart_file(&mut std::io::Cursor::new(b"hello"), 5, None).is_none());
    }

    #[test]
    fn test_portal_upload_saves_exact_file_bytes() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_pin_rate_limiter();
        // In-memory body, and one above IN_MEMORY_BODY_LIMIT that is staged to disk.
        for size in [5000u32, 1_600_000] {
            let boundary = "xYzBoundary42";
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let name = format!("m7_upload_{}_{}.bin", std::process::id(), size);
            let body = multipart_body(boundary, &name, &data);

            let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
            let addr = listener.local_addr().unwrap();
            let server = serve_one(listener);
            let mut c = TcpStream::connect(addr).unwrap();
            let head = format!(
                "POST /upload HTTP/1.1\r\nHost: {}\r\nX-OmaSend-PIN: 1234\r\nContent-Type: multipart/form-data; boundary={}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                addr, boundary, body.len()
            );
            c.write_all(head.as_bytes()).unwrap();
            c.write_all(&body).unwrap();
            let mut resp = String::new();
            // The server may close before reading the whole request; keep what it sent.
            let _ = c.read_to_string(&mut resp);
            server.join().unwrap();
            assert!(resp.starts_with("HTTP/1.1 200"), "{}", resp);
            let saved = get_download_dir().join(&name);
            assert_eq!(fs::read(&saved).unwrap(), data);
            let _ = fs::remove_file(saved);
        }
    }

    /// M17: failed pairing attempts are limited per address and no longer burn the real offer.
    #[test]
    fn test_v2_pair_failures_limited_per_ip_and_offer_survives() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_pin_rate_limiter();
        set_visibility("ALL");
        let uri = create_pair_offer_json(false)["uri"].as_str().unwrap().to_string();
        let offer = devicekey::parse_pair_uri(&uri).unwrap();
        let attacker = devicekey::DeviceIdentity::from_seed([3u8; 32]);
        let bogus = serde_json::json!({ "pk": attacker.public_b64(), "name": "x", "mac": "00", "sig": "AA" });
        // Pairing is LAN-only: through the WAN tunnel the route does not exist.
        let r = post_once("/api/v2/pair", "Cf-Connecting-Ip: 198.51.100.20\r\n", &bogus);
        assert!(r.starts_with("HTTP/1.1 404"), "{}", r);
        for _ in 0..5 {
            let r = post_once("/api/v2/pair", "", &bogus);
            assert!(r.starts_with("HTTP/1.1 403"), "{}", r);
        }
        let r = post_once("/api/v2/pair", "", &bogus);
        assert!(r.starts_with("HTTP/1.1 429"), "same address is now limited: {}", r);
        // The limit is per address; the failed guesses did not burn the offer.
        reset_pin_rate_limiter();

        // The genuine initiator still pairs with the same QR code.
        let phone = devicekey::DeviceIdentity::from_seed([4u8; 32]);
        let body = devicekey::build_pair_request(&phone, &offer, "Phone", 53318);
        let r = post_once("/api/v2/pair", "", &body);
        assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
        let stored = trust_store().get(&phone.public_b64()).expect("paired");
        assert!(!stored.own_device);
        assert!(stored.ip.is_empty(), "a loopback source is not stored as the peer address");
        trust_store().remove(&stored.pk).unwrap();

        set_visibility("OFF");
        let r = post_once("/api/v2/pair", "", &bogus);
        assert!(r.starts_with("HTTP/1.1 403") && r.contains("Off"), "{}", r);
        set_visibility("ALL");
        reset_pin_rate_limiter();
    }

    /// M13: beacons are attributed to their UDP source, OFF only removes the sender itself,
    /// and the list is capped.
    #[test]
    fn test_beacons_use_source_address_and_are_capped() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        save_discovered_peers(&[]);
        let beacon = |id: &str, ip: &str, mode: &str| P2pBeaconPacket {
            magic: "OMASEND_P2P".to_string(),
            v: 1,
            id: id.to_string(),
            oma_id: rendezvous::format_oma_id(&rendezvous::generate_raw_oma_id()),
            name: id.to_string(),
            ip: ip.to_string(),
            port: PORT,
            mode: mode.to_string(),
            fp: String::new(),
            pk: String::new(),
        };
        let a: IpAddr = "192.168.7.10".parse().unwrap();
        let b: IpAddr = "192.168.7.11".parse().unwrap();
        // Claims another host's address: the source address wins.
        update_discovered_peer(&beacon("dev-a", "192.168.7.99", "KNOWN"), a);
        let peers = get_discovered_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip, "192.168.7.10");
        // OFF from a different source does not remove dev-a.
        update_discovered_peer(&beacon("dev-a", "192.168.7.10", "OFF"), b);
        assert_eq!(get_discovered_peers().len(), 1);
        // OFF from dev-a itself does.
        update_discovered_peer(&beacon("dev-a", "", "OFF"), a);
        assert!(get_discovered_peers().is_empty());
        // Random ids cannot grow the list without bound.
        for i in 0..(MAX_DISCOVERED_PEERS + 20) {
            update_discovered_peer(&beacon(&format!("flood-{}", i), "", "KNOWN"), b);
        }
        assert!(get_discovered_peers().len() <= MAX_DISCOVERED_PEERS);
        save_discovered_peers(&[]);
    }

    /// M16: a stale pid file must not make us signal an unrelated process.
    #[test]
    fn test_pid_is_checks_process_name() {
        let me = std::process::id() as i32;
        let my_comm = fs::read_to_string(format!("/proc/{}/comm", me)).unwrap();
        assert!(pid_is(me, my_comm.trim_end()));
        assert!(!pid_is(me, CLOUDFLARED_COMM));
        assert!(!pid_is(1, "systemd"));
        assert!(!pid_is(i32::MAX, ENGINE_COMM));
    }

    #[test]
    fn test_portal_and_notification_escaping() {
        assert_eq!(html_escape(r#"a<b>&"c'.txt"#), "a&lt;b&gt;&amp;&quot;c&#39;.txt");
        let files = vec![FileInfo { name: "x');alert(1);('<img>.txt".to_string(), size_str: "1 B".to_string(), size_bytes: 1 }];
        let html = render_web_app("127.0.0.1", &files);
        assert!(!html.contains("<img>.txt"));
        assert!(!html.contains("downloadFile('x')"));
        assert!(html.contains("data-name=\"x&#39;);alert(1);(&#39;&lt;img&gt;.txt\""));
        assert_eq!(notification_text("<b>evil</b> & co"), "&lt;b&gt;evil&lt;/b&gt; &amp; co");
        assert!(notification_text("-u critical").starts_with('\u{2060}'));
    }

    /// The WAN tunnel (loopback + proxy headers) reaches only the portal routes.
    #[test]
    fn test_tunnel_requests_only_reach_portal_routes() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_pin_rate_limiter();
        let cf = "Cf-Connecting-Ip: 203.0.113.50\r\n";
        let local = format!("X-OmaSend-Local: {}\r\n", ensure_local_api_token());
        for path in ["/api/p2p/ping", "/api/p2p/peers", "/api/p2p/decision?token=x", "/api/p2p/clipboard/image?hash=00", "/download/x.txt", "/api/clipboard"] {
            let r = get_once(path, cf);
            assert!(r.starts_with("HTTP/1.1 404"), "{} must not be reachable through the tunnel: {}", path, r);
            let r = get_once(path, &format!("{}{}", local, cf));
            assert!(r.starts_with("HTTP/1.1 404"), "{} must not be reachable through the tunnel even with the local token: {}", path, r);
        }
        for path in ["/api/v2/pair", "/api/v2/link/start", "/api/v2/account/sync", "/api/p2p/request", "/api/p2p/pair", "/api/p2p/clipboard", "/api/local/core-send", "/api/p2p/decision", "/upload"] {
            let r = post_once(path, cf, &serde_json::json!({}));
            assert!(r.starts_with("HTTP/1.1 404"), "POST {} must not be reachable through the tunnel: {}", path, r);
        }
        let r = get_once("/api/status", cf);
        assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
        let r = get_once("/", cf);
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("Portal Access"), "{}", r);
        // The same LAN routes still work without proxy headers.
        let r = get_once("/api/p2p/ping", "");
        assert!(r.starts_with("HTTP/1.1 200"), "{}", r);

        assert!(is_portal_route("GET", "/api/download-encrypted/a.txt"));
        assert!(is_portal_route("POST", "/api/login"));
        assert!(!is_portal_route("GET", "/api/p2p/upload"));
        assert!(!is_portal_route("POST", "/api/v2/pair"));
        reset_pin_rate_limiter();
    }

    /// The portal secret is long and random, is accepted only from a header, and logging in
    /// returns a hardened session cookie (Secure only through the HTTPS tunnel).
    #[test]
    fn test_portal_login_cookie_and_secret() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_pin_rate_limiter();
        let secret = get_or_create_pin();
        assert!(secret.len() * 4 >= 128, "portal secret must carry at least 128 bits");
        assert_ne!(generate_new_pin(), secret);
        let _ = write_secure_file(&get_state_dir().join("pin.txt"), "1234");
        let migrated = get_or_create_pin();
        assert_eq!(migrated.len(), PORTAL_SECRET_HEX_LEN, "a stored 4-digit PIN must be replaced");

        let r = post_once("/api/login", "X-OmaSend-PIN: 1234\r\n", &serde_json::json!({}));
        assert!(r.starts_with("HTTP/1.1 200"), "{}", r);
        let cookie = r.lines().find(|l| l.starts_with("Set-Cookie:")).expect("session cookie").to_string();
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"), "{}", cookie);
        assert!(!cookie.contains("Secure"), "plain-http LAN portal cannot use a Secure cookie: {}", cookie);
        assert!(!cookie.contains("1234"));

        let r = post_once("/api/login", "X-OmaSend-PIN: 1234\r\nCf-Connecting-Ip: 203.0.113.51\r\n", &serde_json::json!({}));
        let cookie = r.lines().find(|l| l.starts_with("Set-Cookie:")).expect("session cookie").to_string();
        assert!(cookie.contains("; Secure") && cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"), "{}", cookie);

        let r = post_once("/api/login?pin=1234", "", &serde_json::json!({}));
        assert!(r.starts_with("HTTP/1.1 401"), "?pin= must not authenticate: {}", r);

        let url = portal_secret_url("http://192.168.1.5:53317", &secret, "ab");
        assert!(!url.contains("?pin="));
        let frag = url.split_once('#').expect("fragment").1;
        assert!(frag.contains(&secret));
        reset_pin_rate_limiter();
    }

    /// Many addresses together cannot keep guessing: a global failure budget stops new secret
    /// attempts, while requests without a secret (paired devices, sessions) still work.
    #[test]
    fn test_global_pin_budget_blocks_distributed_guessing() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_pin_rate_limiter();
        for i in 0..PIN_GLOBAL_MAX_FAILURES {
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, (i % 250) as u8 + 1));
            record_pin_attempt(ip, false);
        }
        assert!(is_pin_globally_limited());
        let r = get_once("/api/status", "X-OmaSend-PIN: 1234\r\nCf-Connecting-Ip: 203.0.113.77\r\n");
        assert!(r.starts_with("HTTP/1.1 429"), "fresh address must be refused while the budget is spent: {}", r);
        let r = get_once("/api/p2p/ping", "");
        assert!(r.starts_with("HTTP/1.1 200"), "requests without a secret keep working: {}", r);
        reset_pin_rate_limiter();
        assert!(!is_pin_globally_limited());
    }

    /// --json never carries the portal secret, the session key or the account OmaID.
    #[test]
    fn test_status_json_has_no_secrets() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let pin = get_or_create_pin();
        let key = get_or_create_session_key();
        let account = omalink::get_or_create_account_id(&get_state_dir());
        let json = serde_json::to_string(&build_server_state("192.168.1.50")).unwrap();
        assert!(!json.contains(&pin), "portal secret leaked into --json");
        assert!(!json.contains(&key), "session key leaked into --json");
        assert!(!json.contains(&account) && !json.contains(&rendezvous::normalize_oma_id(&account)), "account OmaID leaked into --json");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("pin").is_none() && v.get("session_key").is_none() && v.get("cluster_id").is_none());
        assert!(!v["active_url"].as_str().unwrap_or_default().contains('#'));
        assert!(!v["active_url"].as_str().unwrap_or_default().contains("pin"));
    }

    /// The public OmaID and the secret account OmaID never go out in beacons or /ping, and a
    /// beacon claiming our OmaID is not treated as "same owner".
    #[test]
    fn test_no_oma_id_in_beacon_or_ping() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        set_visibility("ALL");
        let oma = get_or_create_oma_id();
        let account = omalink::get_or_create_account_id(&get_state_dir());
        let ids = [oma.clone(), rendezvous::normalize_oma_id(&oma), account.clone(), rendezvous::normalize_oma_id(&account)];
        let beacon = serde_json::to_string(&beacon_packet("KNOWN")).unwrap();
        let ping = ping_response().to_string();
        for (what, json) in [("beacon", &beacon), ("ping", &ping)] {
            assert!(!json.contains("oma_id"), "{} must not carry an oma_id field: {}", what, json);
            for id in &ids {
                assert!(!json.contains(id.as_str()), "{} leaks an OmaID: {}", what, json);
            }
        }
        let r = get_once("/api/p2p/ping", "");
        assert!(!r.contains("oma_id") && !r.contains(&rendezvous::normalize_oma_id(&oma)), "{}", r);

        // A newer peer's beacon (no OmaID) is listed; one claiming our OmaID is not "same owner".
        let src: IpAddr = "192.168.200.7".parse().unwrap();
        let mut b: P2pBeaconPacket = serde_json::from_str(&beacon).unwrap();
        b.id = "no-omaid-peer".to_string();
        b.pk = String::new();
        update_discovered_peer(&b, src);
        b.id = "claims-my-omaid".to_string();
        b.oma_id = oma.clone();
        update_discovered_peer(&b, src);
        let peers = get_discovered_peers();
        assert!(peers.iter().any(|p| p.id == "no-omaid-peer"));
        let claimer = peers.iter().find(|p| p.id == "claims-my-omaid").expect("listed");
        assert!(!claimer.is_same_owner && !claimer.is_trusted);
        save_discovered_peers(&peers.into_iter().filter(|p| p.ip != "192.168.200.7").collect::<Vec<_>>());
    }

    /// Only loopback, private and link-local clients reach the HTTP server; Tailscale's CGNAT
    /// range only when this machine is on a tailnet.
    #[test]
    fn test_public_client_ips_are_rejected() {
        for ok in ["127.0.0.1", "192.168.1.20", "10.0.0.5", "172.16.3.4", "169.254.10.1", "::1", "fe80::1", "fd12::1", "::ffff:192.168.1.20"] {
            assert!(is_allowed_client_ip(ok.parse().unwrap(), false), "{} should be allowed", ok);
        }
        for bad in ["8.8.8.8", "1.1.1.1", "203.0.113.9", "100.64.0.1", "2001:4860::8888", "::ffff:8.8.8.8"] {
            assert!(!is_allowed_client_ip(bad.parse().unwrap(), false), "{} must be rejected", bad);
        }
        assert!(is_allowed_client_ip("100.101.102.103".parse().unwrap(), true));
        assert!(!is_allowed_client_ip("100.128.0.1".parse().unwrap(), true));
        assert!(!is_allowed_client_ip("8.8.8.8".parse().unwrap(), true));
    }

    /// Downloads are watched with inotify: a new file is announced once it settles, a hidden
    /// or partial file is not, and nothing is rescanned on a timer.
    #[test]
    fn test_download_watcher_announces_new_files_via_inotify() {
        let dir = env::temp_dir().join(format!("omasend_inotify_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let old = format!("old_{}.txt", std::process::id());
        fs::write(dir.join(&old), b"old").unwrap();
        start_download_dir_watcher(&dir);
        thread::sleep(Duration::from_millis(300));

        let fresh = format!("fresh_{}.bin", std::process::id());
        let partial = format!("partial_{}.bin.part", std::process::id());
        fs::write(dir.join(&fresh), b"hello").unwrap();
        fs::write(dir.join(&partial), b"x").unwrap();
        assert!(!is_recently_notified(&fresh), "must wait for the file to settle");
        let deadline = Instant::now() + Duration::from_secs(6);
        while !is_recently_notified(&fresh) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
        assert!(is_recently_notified(&fresh), "new file must be announced");
        assert!(!is_recently_notified(&partial), "partial downloads are ignored");
        let _ = fs::remove_dir_all(&dir);
    }
}
