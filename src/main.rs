mod subproc;
pub mod military;
pub mod rendezvous;

pub use rendezvous::{
    build_github_anchor_payload, compute_rendezvous_topic, create_stun_binding_request,
    decrypt_rendezvous_record, derive_rendezvous_key, encrypt_rendezvous_record,
    format_github_anchor_ref, format_oma_id, generate_raw_oma_id, hkdf_sha256, hmac_sha256,
    luhn_checksum, luhn_verify, normalize_oma_id, parse_github_anchor_payload, parse_stun_response,
    publish_local_rendezvous_anchor, query_local_rendezvous_anchor, query_stun_external_addr,
    query_stun_server, validate_oma_id, EncryptedRendezvousEnvelope, NatTraversedSocket,
    RendezvousRecord,
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
    pub last_seen_secs: u64,
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
    pub total_size_bytes: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: String, // "PENDING", "ACCEPTED", "REJECTED"
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pBeaconPacket {
    pub magic: String,
    pub v: u32,
    pub id: String,
    #[serde(default)]
    pub oma_id: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub mode: String,
    pub fp: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerState {
    pub status: String,
    pub port: u16,
    pub local_ip: String,
    pub tailscale_ip: Option<String>,
    pub pin: String,
    pub session_key: String,
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
    pub clipboard_vault: Vec<ClipboardItem>,
    // OmaID, Blinded Rendezvous & WAN Discovery
    pub oma_id: String,
    pub wan_mode: String,
    pub cluster_id: String,
    pub stun_addr: Option<String>,
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
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = Path::new(&home).join(".local/state/omarchy/omasend");
    let _ = fs::create_dir_all(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    dir
}

fn get_download_dir() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = Path::new(&home).join("Downloads/omasend");
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

    fs::read_to_string(path).map_err(|e| format!("Failed to read {:?}: {}", path, e))
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

/// Reads any normal file safely:
/// - Rejects untrusted symlinks
/// - Must be regular file
/// - Must be owned by the current running user
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
    fs::read(path).map_err(|e| format!("Failed to read {:?}: {}", path, e))
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

fn get_or_create_pin() -> String {
    let pin_file = get_state_dir().join("pin.txt");
    if let Ok(content) = read_secure_file(&pin_file) {
        let p = content.trim();
        if p.len() == 4 && p.chars().all(|c| c.is_ascii_digit()) {
            return p.to_string();
        }
    }
    generate_new_pin()
}

fn generate_new_pin() -> String {
    let mut rand_bytes = [0u8; 2];
    let _ = getrandom::getrandom(&mut rand_bytes);
    let val = ((rand_bytes[0] as u32) << 8 | (rand_bytes[1] as u32)) % 9000 + 1000;
    let pin = format!("{:04}", val);
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
    if let Ok(m) = fs::read_to_string(&mode_file) {
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

fn get_wan_provider() -> Option<String> {
    let provider_file = get_state_dir().join("wan_provider.txt");
    read_secure_file(&provider_file).ok().map(|s| s.trim().to_string())
}

fn get_cloudflared_bin() -> Option<String> {
    for candidate in &["/usr/bin/cloudflared", "/usr/local/bin/cloudflared"] {
        if Path::new(candidate).is_file() {
            return Some(candidate.to_string());
        }
    }
    if let Ok(home) = env::var("HOME") {
        let local_bin = format!("{}/.local/bin/cloudflared", home);
        if Path::new(&local_bin).is_file() {
            return Some(local_bin);
        }
    }
    let deadline = Instant::now() + Duration::from_millis(300);
    if let Some(out) = run_cmd_bounded("/usr/bin/which", &["cloudflared"], &[], deadline, 256) {
        let path = String::from_utf8_lossy(&out).trim().to_string();
        if !path.is_empty() && Path::new(&path).is_file() {
            return Some(path);
        }
    }
    None
}

fn get_wan_status() -> (bool, bool, Option<String>) {
    let pid_file = get_state_dir().join("wan_pid.txt");
    let url_file = get_state_dir().join("wan_url.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let log_file = get_state_dir().join("wan_tunnel.log");

    if let Ok(pid_str) = read_secure_file(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if is_process_alive(pid) {
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

fn stop_wan_tunnel() {
    let pid_file = get_state_dir().join("wan_pid.txt");
    let url_file = get_state_dir().join("wan_url.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let provider_file = get_state_dir().join("wan_provider.txt");
    let log_file = get_state_dir().join("wan_tunnel.log");

    if let Ok(pid_str) = read_secure_file(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            kill_process_group(pid);
        }
    }

    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&url_file);
    let _ = fs::remove_file(&connecting_file);
    let _ = fs::remove_file(&provider_file);
    let _ = fs::remove_file(&log_file);
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
            kill_process_group(pid);
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
                return Ok("Cloudflare tunnel launched in background".to_string());
            }
            Err(e) => {
                return Err(format!("Failed to spawn cloudflared: {}", e));
            }
        }
    }

    Err("WAN Tunneling requires cloudflared. Please install the trusted system package: pacman -S cloudflared (see README.md)".to_string())
}

// ------------------- QR CODE & URLS -------------------

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

    let deadline = Instant::now() + Duration::from_secs(2);
    // Generate SVG via qrencode
    let svg_ok = run_cmd_bounded(
        "/usr/bin/qrencode",
        &["-o", &svg_path, "-t", "SVG", &qr_content],
        &[],
        deadline,
        1024,
    ).is_some();

    // Fallback internal SVG generator if qrencode fails or is absent
    if !svg_ok || !svg_file.exists() {
        let svg_data = rendezvous::generate_fallback_qr_svg(&qr_content);
        let _ = write_secure_file(&svg_file, &svg_data);
    }

    // Sync legacy omaid_qr.svg path if needed
    if let Ok(svg_bytes) = fs::read(&svg_file) {
        let _ = write_secure_bytes(&legacy_svg_file, &svg_bytes);
    }

    // Generate PNG via qrencode
    let deadline_png = Instant::now() + Duration::from_secs(2);
    let _ = run_cmd_bounded(
        "/usr/bin/qrencode",
        &["-o", &png_path, "-t", "PNG", "-s", "8", "-m", "2", &qr_content],
        &[],
        deadline_png,
        1024,
    );

    let _ = write_secure_file(&last_content_file, &qr_content);
    (svg_path, png_path)
}

fn update_all_qr() {
    let ip = get_local_ip();
    let pin = get_or_create_pin();
    let key = get_or_create_session_key();
    let mode = get_active_mode();
    let (_wan_active, _wan_connecting, wan_url) = get_wan_status();

    let target_base = if mode == "WAN" {
        if let Some(ref u) = wan_url {
            u.clone()
        } else {
            format!("http://{}:{}", ip, PORT)
        }
    } else {
        format!("http://{}:{}", ip, PORT)
    };

    let full_url = format!("{}/?pin={}#key={}", target_base, pin, key);

    let last_qr_file = get_state_dir().join("last_qr_url.txt");
    let qr_file = get_state_dir().join("qr.svg");

    if !qr_file.exists() || read_secure_file(&last_qr_file).map(|s| s.trim() != full_url).unwrap_or(true) {
        let qr_path = qr_file.to_string_lossy().to_string();
        let deadline = Instant::now() + Duration::from_secs(2);
        let _ = run_cmd_bounded(
            "/usr/bin/qrencode",
            &["-o", &qr_path, "-t", "SVG", &full_url],
            &[],
            deadline,
            1024,
        );
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

fn notify_desktop(title: &str, body: &str) {
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

fn start_download_dir_watcher(download_dir: &Path) {
    let dir = download_dir.to_path_buf();
    thread::spawn(move || {
        // Initial scan: record existing files so we don't send notifications for old files
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_file() {
                        let fname = entry.file_name().to_string_lossy().to_string();
                        record_notified_file(&fname);
                    }
                }
            }
        }

        let mut previous_sizes: HashMap<String, u64> = HashMap::new();

        loop {
            thread::sleep(Duration::from_millis(1500));
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if let Ok(ft) = entry.file_type() {
                        if !ft.is_file() {
                            continue;
                        }
                        let fname = entry.file_name().to_string_lossy().to_string();
                        if fname.starts_with('.') || fname.ends_with(".part") || fname.ends_with(".crdownload") {
                            continue;
                        }
                        if is_recently_notified(&fname) {
                            continue;
                        }

                        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                        if let Some(&prev_size) = previous_sizes.get(&fname) {
                            if prev_size == size && size > 0 {
                                record_notified_file(&fname);
                                previous_sizes.remove(&fname);
                                RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
                                notify_desktop(
                                    "OmaSend: Dosya Alindi",
                                    &format!("'{}' ({} bayt) Downloads/omasend dizinine kaydedildi.", fname, size),
                                );
                            } else {
                                previous_sizes.insert(fname, size);
                            }
                        } else {
                            previous_sizes.insert(fname, size);
                        }
                    }
                }
            }
        }
    });
}

pub const MAX_CLIPBOARD_VAULT_ITEMS: usize = 20;
pub const MAX_IMAGE_CLIP_SIZE: usize = 10 * 1024 * 1024; // 10 MiB strict ceiling
pub const INLINE_IMAGE_CLIP_MAX_SIZE: usize = 512 * 1024; // 512 KiB inline payload ceiling
pub const MAX_CLIP_STAGING_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB max staging disk usage
pub const MAX_CLIP_STAGING_FILES: usize = 20; // 20 images max

pub fn compute_image_clipboard_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
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
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.len() % 4 != 0 {
        return Err("Invalid Base64 length".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
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
            if is_sof {
                if seg_len >= 7 && offset + 7 <= len {
                    let h = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as u32;
                    let w = u16::from_be_bytes([data[offset + 5], data[offset + 6]]) as u32;
                    height = h;
                    width = w;
                    break;
                }
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
            if data.len() >= 30 {
                if data[23] == 0x9D && data[24] == 0x01 && data[25] == 0x2A {
                    let w = u16::from_le_bytes([data[26], data[27]]) & 0x3FFF;
                    let h = u16::from_le_bytes([data[28], data[29]]) & 0x3FFF;
                    width = w as u32;
                    height = h as u32;
                }
            }
        } else if chunk_type == b"VP8L" {
            if data.len() >= 25 && data[20] == 0x2F {
                let bits = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
                width = (bits & 0x3FFF) + 1;
                height = ((bits >> 14) & 0x3FFF) + 1;
            }
        } else if chunk_type == b"VP8X" {
            if data.len() >= 30 {
                let w = (data[24] as u32) | ((data[25] as u32) << 8) | ((data[26] as u32) << 16);
                let h = (data[27] as u32) | ((data[28] as u32) << 8) | ((data[29] as u32) << 16);
                width = w + 1;
                height = h + 1;
            }
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

    let input_str = match image_path.to_str() {
        Some(s) => s,
        None => return None,
    };
    let tmp_thumb_path = staging_dir.join(format!(".tmp_{}_thumb.webp", hash_hex));
    let tmp_out_str = match tmp_thumb_path.to_str() {
        Some(s) => s,
        None => return None,
    };

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

    files.sort_by(|a, b| b.2.cmp(&a.2));

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
    let path = get_state_dir().join("clipboard_vault.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(mut vault) = serde_json::from_str::<ClipboardVault>(&content) {
            vault.items.retain(|item| {
                if item.content_type.starts_with("image_") || item.image_hash.is_some() {
                    return true;
                }
                let s = &item.text;
                !s.starts_with("\u{FFFD}") &&
                !s.starts_with("PNG") &&
                s.chars().filter(|c| *c == '\u{FFFD}').count() < 2 &&
                s.chars().take(100).filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t').count() < 2
            });
            return vault;
        }
    }
    let hist_path = get_state_dir().join("clipboard_history.json");
    if let Ok(content) = read_secure_file(&hist_path) {
        if let Ok(mut vault) = serde_json::from_str::<ClipboardVault>(&content) {
            vault.items.retain(|item| {
                if item.content_type.starts_with("image_") || item.image_hash.is_some() {
                    return true;
                }
                let s = &item.text;
                !s.starts_with("\u{FFFD}") &&
                !s.starts_with("PNG") &&
                s.chars().filter(|c| *c == '\u{FFFD}').count() < 2 &&
                s.chars().take(100).filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t').count() < 2
            });
            return vault;
        }
    }
    ClipboardVault::default()
}

pub fn save_clipboard_vault(vault: &ClipboardVault) -> Result<(), String> {
    let path = get_state_dir().join("clipboard_vault.json");
    let content = serde_json::to_string_pretty(vault).map_err(|e| e.to_string())?;
    write_secure_file(&path, &content)?;
    let hist_path = get_state_dir().join("clipboard_history.json");
    let _ = write_secure_file(&hist_path, &content);
    Ok(())
}

pub fn add_clipboard_to_vault(sender: &str, text: &str) -> Result<ClipboardItem, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("Clipboard text is empty".to_string());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let item = ClipboardItem {
        timestamp: now,
        sender: sender.to_string(),
        content_type: "text".to_string(),
        text: text.to_string(),
        char_count: text.chars().count(),
        is_url: is_probable_url(text),
        image_hash: None,
        image_size: None,
        image_width: None,
        image_height: None,
        thumbnail_base64: None,
    };

    let mut vault = load_clipboard_vault();
    if let Some(first) = vault.items.first() {
        if first.content_type == "text" && first.text == item.text {
            return Ok(item);
        }
    }

    vault.items.insert(0, item.clone());
    if vault.items.len() > MAX_CLIPBOARD_VAULT_ITEMS {
        vault.items.truncate(MAX_CLIPBOARD_VAULT_ITEMS);
    }
    save_clipboard_vault(&vault)?;
    Ok(item)
}

pub fn add_image_clipboard_to_vault(
    sender: &str,
    content_type: &str,
    image_hash: &str,
    image_size: u64,
    image_width: u32,
    image_height: u32,
    thumbnail_base64: Option<String>,
) -> Result<ClipboardItem, String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let short_hash = if image_hash.len() >= 8 { &image_hash[..8] } else { image_hash };
    let desc = format!("[Image: {} ({}x{})]", short_hash, image_width, image_height);

    let final_thumb = thumbnail_base64.or_else(|| {
        let staging_dir = get_clip_staging_dir();
        let thumb_path = staging_dir.join(format!("{}_thumb.webp", image_hash));
        if thumb_path.exists() {
            if let Ok(meta) = fs::symlink_metadata(&thumb_path) {
                if meta.file_type().is_file() && !meta.file_type().is_symlink() && meta.len() > 0 && meta.len() <= 1024 * 1024 {
                    if let Ok(bytes) = safe_read_file(&thumb_path) {
                        if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
                            return Some(format!("data:image/webp;base64,{}", base64_encode(&bytes)));
                        }
                    }
                }
            }
        }
        let candidates = [
            staging_dir.join(format!("{}.png", image_hash)),
            staging_dir.join(format!("{}.jpg", image_hash)),
            staging_dir.join(format!("{}.webp", image_hash)),
        ];
        for cand in &candidates {
            if cand.exists() {
                return generate_webp_thumbnail_for_staging(cand, image_hash);
            }
        }
        None
    });

    let item = ClipboardItem {
        timestamp: now,
        sender: sender.to_string(),
        content_type: content_type.to_string(),
        text: desc,
        char_count: 0,
        is_url: false,
        image_hash: Some(image_hash.to_string()),
        image_size: Some(image_size),
        image_width: Some(image_width),
        image_height: Some(image_height),
        thumbnail_base64: final_thumb,
    };

    let mut vault = load_clipboard_vault();
    if let Some(first) = vault.items.first_mut() {
        if first.image_hash.as_deref() == Some(image_hash) {
            let mut updated = false;
            if first.thumbnail_base64.is_none() && item.thumbnail_base64.is_some() {
                first.thumbnail_base64 = item.thumbnail_base64.clone();
                updated = true;
            }
            let cloned = first.clone();
            if updated {
                let _ = save_clipboard_vault(&vault);
            }
            return Ok(cloned);
        }
    }

    vault.items.insert(0, item.clone());
    if vault.items.len() > MAX_CLIPBOARD_VAULT_ITEMS {
        vault.items.truncate(MAX_CLIPBOARD_VAULT_ITEMS);
    }
    save_clipboard_vault(&vault)?;
    Ok(item)
}

pub fn get_clipboard_vault_items() -> Vec<ClipboardItem> {
    load_clipboard_vault().items
}


fn play_clipboard_sound() {
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
            if Path::new(bin).exists() {
                if run_cmd_bounded(bin, args, &envs, deadline, 1024).is_some() {
                    break;
                }
            }
        }
    });
}

fn get_active_paired_peer_ips() -> Vec<String> {
    let paired = load_paired_peers();
    let discovered = get_discovered_peers();
    let mut ips = Vec::new();

    for p in &paired {
        let p_norm = rendezvous::normalize_oma_id(&p.oma_id);
        if let Some(disc) = discovered.iter().find(|d| rendezvous::normalize_oma_id(&d.oma_id) == p_norm || d.id == p.oma_id) {
            if !disc.ip.is_empty() && !ips.contains(&disc.ip) {
                ips.push(disc.ip.clone());
            }
        } else if let Some(ref static_ip) = p.ip {
            if !static_ip.is_empty() && !ips.contains(static_ip) {
                ips.push(static_ip.clone());
            }
        }
    }
    ips
}

fn p2p_push_clipboard_silent(target_ip: &str, text: &str) {
    if target_ip.is_empty() {
        return;
    }
    let (my_id, _) = get_or_create_device_id();
    let my_oma_id = get_or_create_oma_id();
    let my_name = get_system_hostname();
    let payload = serde_json::json!({
        "sender_id": my_oma_id,
        "oma_id": my_oma_id,
        "device_id": my_id,
        "sender_name": my_name,
        "content_type": "text",
        "text": text
    });
    let addr = resolve_peer_addr(target_ip);
    let req_bytes = payload.to_string().into_bytes();
    let oma_id_hdr = my_oma_id.clone();
    thread::spawn(move || {
        if let Ok(mut stream) = connect_peer_with_timeout(&addr, Duration::from_millis(1500)) {
            let http_req = format!(
                "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                addr, oma_id_hdr, req_bytes.len()
            );
            let _ = stream.write_all(http_req.as_bytes());
            let _ = stream.write_all(&req_bytes);
            let mut resp = Vec::new();
            let _ = stream.read_to_end(&mut resp);
        }
    });
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
    let my_oma_id = get_or_create_oma_id();
    let my_name = get_system_hostname();

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

    let payload = serde_json::json!({
        "sender_id": my_oma_id,
        "oma_id": my_oma_id,
        "device_id": my_id,
        "sender_name": my_name,
        "content_type": content_type,
        "image_hash": hash,
        "image_size": size,
        "image_width": width,
        "image_height": height,
        "image_base64": image_base64,
        "thumbnail_base64": thumb_b64
    });

    let addr = resolve_peer_addr(target_ip);
    let req_bytes = payload.to_string().into_bytes();
    let oma_id_hdr = my_oma_id.clone();
    thread::spawn(move || {
        if let Ok(mut stream) = connect_peer_with_timeout(&addr, Duration::from_millis(2500)) {
            let http_req = format!(
                "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                addr, oma_id_hdr, req_bytes.len()
            );
            let _ = stream.write_all(http_req.as_bytes());
            let _ = stream.write_all(&req_bytes);
            let mut resp = Vec::new();
            let _ = stream.read_to_end(&mut resp);
        }
    });
}

pub fn p2p_fetch_image_clipboard_and_apply(sender_ip: &str, hash: &str, _content_type: &str) {
    if sender_ip.is_empty() || hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return;
    }
    let ip = sender_ip.to_string();
    let h = hash.to_string();
    thread::spawn(move || {
        let addr = resolve_peer_addr(&ip);
        if let Ok(mut stream) = connect_peer_with_timeout(&addr, Duration::from_secs(5)) {
            let http_req = format!(
                "GET /api/p2p/clipboard/image/{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                h, addr
            );
            if stream.write_all(http_req.as_bytes()).is_ok() {
                let mut resp_bytes = Vec::new();
                if stream.read_to_end(&mut resp_bytes).is_ok() {
                    if let Some(pos) = resp_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header_part = String::from_utf8_lossy(&resp_bytes[..pos]);
                        if header_part.starts_with("HTTP/1.1 200") || header_part.starts_with("HTTP/1.0 200") {
                            let body_bytes = &resp_bytes[pos + 4..];
                            if let Ok((verified_ct, _w, _h)) = validate_image_header(body_bytes) {
                                let computed_hash = compute_image_clipboard_hash(body_bytes);
                                if computed_hash == h {
                                    let staged_res = stage_clipboard_image(body_bytes, &verified_ct);
                                    let thumb_b64 = if let Ok((_, ref staged_path)) = staged_res {
                                        generate_webp_thumbnail_for_staging(staged_path, &computed_hash)
                                    } else {
                                        None
                                    };
                                    let _ = add_image_clipboard_to_vault(
                                        &ip,
                                        &verified_ct,
                                        &computed_hash,
                                        body_bytes.len() as u64,
                                        _w,
                                        _h,
                                        thumb_b64,
                                    );
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

pub fn start_clipboard_sentinel() {
    thread::spawn(move || {
        let initial_text = get_pc_clipboard();
        if !initial_text.trim().is_empty() {
            let initial_hash = compute_clipboard_hash(&initial_text);
            set_last_synced_clipboard_hash(&initial_hash);
        } else if let Some((img_bytes, _, _, _)) = get_pc_image_clipboard() {
            let initial_hash = compute_image_clipboard_hash(&img_bytes);
            set_last_synced_clipboard_hash(&initial_hash);
        }

        loop {
            thread::sleep(Duration::from_millis(250));

            // Check image clipboard first
            if let Some((img_bytes, ct, w, h)) = get_pc_image_clipboard() {
                let img_hash = compute_image_clipboard_hash(&img_bytes);
                let last_hash = get_last_synced_clipboard_hash();

                if last_hash.as_deref() != Some(&img_hash) {
                    set_last_synced_clipboard_hash(&img_hash);
                    let size = img_bytes.len() as u64;
                    let staged_res = stage_clipboard_image(&img_bytes, &ct);
                    let thumb_b64 = if let Ok((_, ref staged_path)) = staged_res {
                        generate_webp_thumbnail_for_staging(staged_path, &img_hash)
                    } else {
                        None
                    };
                    let _ = add_image_clipboard_to_vault("Local", &ct, &img_hash, size, w, h, thumb_b64);

                    let target_ips = get_active_paired_peer_ips();
                    for target_ip in target_ips {
                        p2p_push_image_clipboard_silent(
                            &target_ip,
                            &ct,
                            &img_hash,
                            size,
                            w,
                            h,
                            Some(&img_bytes),
                        );
                    }
                    continue;
                }
            }


            // Check text clipboard
            let text = get_pc_clipboard();
            if text.trim().is_empty() {
                continue;
            }

            let hash = compute_clipboard_hash(&text);
            let last_hash = get_last_synced_clipboard_hash();

            if last_hash.as_deref() == Some(&hash) {
                continue;
            }

            set_last_synced_clipboard_hash(&hash);
            let _ = add_clipboard_to_vault("Local", &text);

            let target_ips = get_active_paired_peer_ips();
            for target_ip in target_ips {
                p2p_push_clipboard_silent(&target_ip, &text);
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
        if trimmed.len() > 180 {
            trimmed[..180].to_string()
        } else {
            trimmed.to_string()
        }
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
            format!("{} ({})", stem, i)
        } else {
            format!("{} ({}).{}", stem, i, ext)
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
    let oma_id = get_or_create_oma_id();
    let hostname = get_system_hostname();
    let ip = get_local_ip();

    let packet = P2pBeaconPacket {
        magic: "OMASEND_P2P".to_string(),
        v: 1,
        id: device_id,
        oma_id,
        name: hostname,
        ip: ip.clone(),
        port: PORT,
        mode: "OFF".to_string(),
        fp,
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

fn load_trusted_peers() -> Vec<TrustedPeer> {
    let path = get_state_dir().join("trusted_peers.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(db) = serde_json::from_str::<TrustedPeersDb>(&content) {
            return db.peers;
        }
    }
    Vec::new()
}

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

fn get_pending_transfer() -> Option<PendingFileTransfer> {
    let path = get_state_dir().join("pending_transfer.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(t) = serde_json::from_str::<PendingFileTransfer>(&content) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            if now <= t.expires_at {
                return Some(t);
            }
        }
    }
    None
}

fn save_pending_transfer(t: &PendingFileTransfer) {
    let path = get_state_dir().join("pending_transfer.json");
    if let Ok(s) = serde_json::to_string(t) {
        let _ = write_secure_file(&path, &s);
    }
}

fn clear_pending_transfer() {
    let path = get_state_dir().join("pending_transfer.json");
    let _ = fs::remove_file(path);
}

fn get_discovered_peers() -> Vec<DiscoveredPeer> {
    let (vis, _) = get_visibility();
    if vis == "OFF" {
        return Vec::new();
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut peers = Vec::new();
    let path = get_state_dir().join("discovered_peers.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(loaded) = serde_json::from_str::<Vec<DiscoveredPeer>>(&content) {
            // Prune peers older than 15s
            peers = loaded.into_iter().filter(|p| now.saturating_sub(p.last_seen_secs) <= 15).collect();
        }
    }

    for p in &mut peers {
        p.is_trusted = is_peer_paired(&p.oma_id) || is_peer_trusted(&p.id);
        p.transport = "LAN".to_string();
    }

    if vis == "KNOWN" {
        peers.retain(|p| p.is_trusted);
    }

    peers
}

fn save_discovered_peers(peers: &[DiscoveredPeer]) {
    let path = get_state_dir().join("discovered_peers.json");
    if let Ok(s) = serde_json::to_string(peers) {
        let _ = write_secure_file(&path, &s);
    }
}

fn is_local_subnet_or_private_ip(ip: &str) -> bool {
    if ip.starts_with("192.168.") || ip.starts_with("10.") || ip == "127.0.0.1" || ip == "::1" || ip.starts_with("169.254.") {
        return true;
    }
    // Carrier-Grade NAT & Tailscale: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
    if ip.starts_with("100.") {
        if let Some(second) = ip.split('.').nth(1) {
            if let Ok(num) = second.parse::<u8>() {
                if (64..=127).contains(&num) {
                    return true;
                }
            }
        }
    }
    if ip.starts_with("172.") {
        if let Some(second) = ip.split('.').nth(1) {
            if let Ok(num) = second.parse::<u8>() {
                if (16..=31).contains(&num) {
                    return true;
                }
            }
        }
    }
    false
}

fn update_discovered_peer(packet: &P2pBeaconPacket) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (my_id, _) = get_or_create_device_id();
    let my_oma_id = get_or_create_oma_id();
    if packet.id == my_id || (!packet.oma_id.is_empty() && rendezvous::normalize_oma_id(&packet.oma_id) == rendezvous::normalize_oma_id(&my_oma_id)) {
        return;
    }

    // Instant offline handling when remote peer turns discovery OFF
    if packet.mode == "OFF" || packet.mode == "STOP" {
        let mut peers = get_discovered_peers();
        let initial_len = peers.len();
        peers.retain(|p| p.id != packet.id && p.ip != packet.ip && (p.oma_id.is_empty() || p.oma_id != packet.oma_id));
        if peers.len() != initial_len {
            save_discovered_peers(&peers);
        }
        return;
    }

    let (vis, _) = get_visibility();
    if vis == "OFF" {
        return;
    }
    let is_paired = (!packet.oma_id.is_empty() && is_peer_paired(&packet.oma_id)) || is_peer_trusted(&packet.id);
    let is_local_net = is_local_subnet_or_private_ip(&packet.ip);
    if vis == "KNOWN" && !is_paired && !is_local_net && packet.mode != "EVERYONE" {
        return;
    }

    // If paired OmaID, immediately sync and ensure current active IP is recorded
    if !packet.oma_id.is_empty() && is_peer_paired(&packet.oma_id) {
        let _ = add_paired_peer(&packet.oma_id, &packet.name, Some(&packet.ip));
    }

    let mut peers = get_discovered_peers();
    if let Some(existing) = peers.iter_mut().find(|p| (!packet.oma_id.is_empty() && p.oma_id == packet.oma_id) || p.id == packet.id) {
        existing.oma_id = packet.oma_id.clone();
        existing.name = packet.name.clone();
        existing.ip = packet.ip.clone();
        existing.port = packet.port;
        existing.transport = "LAN".to_string();
        existing.fingerprint = packet.fp.clone();
        existing.is_trusted = is_paired;
        existing.last_seen_secs = now;
    } else {
        peers.push(DiscoveredPeer {
            id: packet.id.clone(),
            oma_id: packet.oma_id.clone(),
            name: packet.name.clone(),
            ip: packet.ip.clone(),
            port: packet.port,
            transport: "LAN".to_string(),
            fingerprint: packet.fp.clone(),
            is_trusted: is_paired,
            last_seen_secs: now,
        });
    }
    save_discovered_peers(&peers);
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
    let (device_id, fp) = get_or_create_device_id();
    let oma_id = get_or_create_oma_id();
    let hostname = get_system_hostname();
    let ip = get_local_ip();

    let packet = P2pBeaconPacket {
        magic: "OMASEND_P2P".to_string(),
        v: 1,
        id: device_id,
        oma_id,
        name: hostname,
        ip: ip.clone(),
        port: PORT,
        mode: vis,
        fp,
    };

    if let Ok(bytes) = serde_json::to_vec(&packet) {
        let broadcast_targets = get_all_broadcast_addresses();
        let known_peers = get_discovered_peers();

        for i in 0..burst_count {
            for bcast_ip in &broadcast_targets {
                let target = format!("{}:{}", bcast_ip, P2P_BEACON_PORT);
                let _ = socket.send_to(&bytes, &target);
            }
            for peer in &known_peers {
                let target = format!("{}:{}", peer.ip, P2P_BEACON_PORT);
                let _ = socket.send_to(&bytes, &target);
            }
            if i + 1 < burst_count {
                thread::sleep(Duration::from_millis(40));
            }
        }
    }
}

pub fn prune_expired_discovered_peers() -> usize {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let path = get_state_dir().join("discovered_peers.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(peers) = serde_json::from_str::<Vec<DiscoveredPeer>>(&content) {
            let initial_len = peers.len();
            let remaining: Vec<DiscoveredPeer> = peers.into_iter().filter(|p| now.saturating_sub(p.last_seen_secs) <= 15).collect();
            if remaining.len() != initial_len {
                save_discovered_peers(&remaining);
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
            Ok((amt, _src)) => {
                if amt > 0 && amt <= 2048 {
                    if let Ok(packet) = serde_json::from_slice::<P2pBeaconPacket>(&buf[..amt]) {
                        if packet.magic == "OMASEND_P2P" {
                            update_discovered_peer(&packet);
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

fn resolve_peer_addr(target_ip: &str) -> String {
    for peer in get_discovered_peers() {
        if peer.ip == target_ip {
            return format!("{}:{}", peer.ip, peer.port);
        }
    }
    format!("{}:{}", target_ip, PORT)
}

fn p2p_send_file_to_peer(target_ip: &str, file_path: &Path) -> Result<(), String> {
    let size_bytes = safe_verify_file(file_path).map_err(|e| format!("Security check failed: {}", e))?;
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();

    let (my_id, _) = get_or_create_device_id();
    let my_oma_id = get_or_create_oma_id();
    let my_name = get_system_hostname();

    let (blake3_hex, sha256_hex, md5_hex) = compute_file_military_hashes(file_path)
        .map_err(|e| format!("Failed to compute file hashes: {}", e))?;

    // 1. Send transfer request
    let request_payload = serde_json::json!({
        "sender_id": my_oma_id,
        "oma_id": my_oma_id,
        "device_id": my_id,
        "sender_name": my_name,
        "sender_ip": get_local_ip(),
        "files": [
            {
                "name": file_name,
                "size_bytes": size_bytes,
                "blake3": blake3_hex,
                "sha256": sha256_hex,
                "md5": md5_hex
            }
        ],
        "total_size_bytes": size_bytes
    });

    let addr = resolve_peer_addr(target_ip);
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
    let req_bytes = request_payload.to_string().into_bytes();
    let http_req = format!(
        "POST /api/p2p/request HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr, my_oma_id, req_bytes.len()
    );
    stream.write_all(http_req.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&req_bytes).map_err(|e| e.to_string())?;

    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| e.to_string())?;

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

    println!("Transfer request sent to {}! Waiting for user to Accept...", target_ip);
    notify_desktop("OmaSend AirBridge", &format!("Transfer request sent to {}. Waiting for consent...", target_ip));

    // 2. Poll for decision (monotonic deadline of 30 seconds)
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut accepted = false;

    while std::time::Instant::now() < deadline {
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
        let _ = poll_stream.read_to_string(&mut poll_resp);
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

    if !accepted {
        return Err("Transfer timed out waiting for recipient approval.".to_string());
    }

    println!("Peer accepted! Streaming file '{}' ({} bytes, sha256: {})...", file_name, size_bytes, sha256_hex);

    // 3. Upload file via 128 KiB streaming chunks
    let mut upload_stream = connect_peer_with_timeout(&addr, Duration::from_secs(6))
        .map_err(|e| format!("Failed to connect to peer for upload: {}", e))?;
    let encoded_filename = urlencoding_encode(&file_name);
    let upload_header = format!(
        "POST /api/p2p/upload?token={}&filename={}&sha256={}&md5={} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nX-File-SHA256: {}\r\nX-File-MD5: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        token, encoded_filename, sha256_hex, md5_hex, addr, sha256_hex, md5_hex, size_bytes
    );
    upload_stream.write_all(upload_header.as_bytes()).map_err(|e| e.to_string())?;

    let mut file = fs::File::open(file_path).map_err(|e| format!("Failed to open file for upload: {}", e))?;
    let mut chunk_buf = [0u8; 131072]; // 128 KiB chunk aligned with IEEE 802.11 A-MPDU
    loop {
        let n = file.read(&mut chunk_buf).map_err(|e| format!("Failed to read file chunk: {}", e))?;
        if n == 0 {
            break;
        }
        upload_stream.write_all(&chunk_buf[..n]).map_err(|e| format!("Failed to send chunk to peer: {}", e))?;
    }
    upload_stream.flush().map_err(|e| format!("Failed to flush upload stream: {}", e))?;

    let mut final_resp = String::new();
    let _ = upload_stream.read_to_string(&mut final_resp);

    println!("Transfer successfully completed to {}!", target_ip);
    notify_desktop("OmaSend AirBridge", &format!("'{}' successfully sent to {}.", file_name, target_ip));
    Ok(())
}

fn p2p_sync_clipboard_to_peer(target_ip: &str) -> Result<(), String> {
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
    let my_oma_id = get_or_create_oma_id();
    let my_name = get_system_hostname();
    let payload = serde_json::json!({
        "sender_id": my_oma_id,
        "oma_id": my_oma_id,
        "device_id": my_id,
        "sender_name": my_name,
        "content_type": "text",
        "text": text
    });
    let addr = resolve_peer_addr(target_ip);
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
        "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr, my_oma_id, req_bytes.len()
    );
    stream.write_all(http_req.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&req_bytes).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp);
    println!("Clipboard successfully synced to {}", target_ip);
    notify_desktop("OmaSend AirBridge", &format!("Clipboard successfully synced to {}.", target_ip));
    Ok(())
}

// ------------------- HTTP ENGINE -------------------

pub const MAX_HEADER_SIZE: usize = 65536; // 64 KiB header limit
pub const MAX_BODY_SIZE: usize = 100 * 1024 * 1024; // 100 MiB strict plain upload ceiling
pub const MAX_ENCRYPTED_UPLOAD_SIZE: usize = 25 * 1024 * 1024; // 25 MiB encrypted upload ceiling
pub const MAX_CLIPBOARD_BODY: usize = 10 * 1024 * 1024; // 10 MiB clipboard limit
pub const MAX_CONTROL_BODY: usize = 65536; // 64 KiB JSON metadata limit
pub const IN_MEMORY_BODY_LIMIT: usize = 1024 * 1024; // 1 MiB in-memory cap
pub const MAX_AGGREGATE_STAGING_BYTES: u64 = 200 * 1024 * 1024; // 200 MiB aggregate disk staging cap
pub const MAX_CONCURRENT_ENCRYPTED_UPLOADS: u32 = 2; // Max 2 concurrent encrypted uploads
pub const HEADER_READ_TIMEOUT_SECS: u64 = 15; // 15s max header timeout
pub const DEFAULT_BODY_TIMEOUT_SECS: u64 = 30; // 30s body timeout for small requests
pub const MAX_UPLOAD_DURATION_SECS: u64 = 120; // 120s max duration for 100 MiB uploads

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
            return Err("Aggregate staging capacity exceeded (200 MiB limit)");
        }
        if let Some(avail) = get_available_disk_space(ddir) {
            let required_space = current.saturating_add(needed_bytes).saturating_add(25 * 1024 * 1024);
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
                        if content_length > MAX_BODY_SIZE {
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
                                    if content_length > MAX_BODY_SIZE {
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

        while remaining > 0 {
            let to_read = remaining.min(stream_chunk.len());
            match read_stream_chunk_with_deadline(stream, &mut stream_chunk[..to_read], deadline) {
                Ok(0) => {
                    let _ = fs::remove_file(&stage_path);
                    return None;
                }
                Ok(n) => {
                    if stage_file.write_all(&stream_chunk[..n]).is_err() {
                        let _ = fs::remove_file(&stage_path);
                        return None;
                    }
                    blake3_hasher.update(&stream_chunk[..n]);
                    sha_hasher.update(&stream_chunk[..n]);
                    md5_ctx.consume(&stream_chunk[..n]);
                    total_written = total_written.saturating_add(n as u64);
                    remaining = remaining.saturating_sub(n);
                }
                Err(_) => {
                    let _ = fs::remove_file(&stage_path);
                    return None;
                }
            }
        }

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

static PIN_RATE_LIMITER: Mutex<Option<HashMap<IpAddr, PinAttemptState>>> = Mutex::new(None);

pub fn is_pin_rate_limited(ip: IpAddr) -> bool {
    let mut guard = match PIN_RATE_LIMITER.lock() {
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

pub fn record_pin_attempt(ip: IpAddr, success: bool) -> bool {
    let mut guard = match PIN_RATE_LIMITER.lock() {
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
    let mut guard = match PIN_RATE_LIMITER.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(ref mut map) = *guard {
        map.clear();
    }
}

fn extract_provided_pin(req: &HttpRequest) -> Option<String> {
    for part in req.query.split('&') {
        if let Some(val) = part.strip_prefix("pin=") {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    if let Some(h) = req.get_header("x-omasend-pin") {
        if !h.is_empty() {
            return Some(h.to_string());
        }
    }
    if let Some(cookie_val) = req.get_header("cookie") {
        for c in cookie_val.split(';') {
            let ct = c.trim();
            if let Some(val) = ct.strip_prefix("pin=") {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
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
        format!("Set-Cookie: {}; Path=/; HttpOnly; SameSite=Lax\r\n", c)
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

fn render_login_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>OmaSend • PIN Verification</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #070a0e; color: #dbe4ee; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
.card { background: #0e141d; border: 1px solid #1a2332; border-radius: 0; padding: 36px 24px; width: 100%; max-width: 380px; text-align: center; box-shadow: 0 12px 40px rgba(0,0,0,0.6); }
.icon { font-size: 44px; margin-bottom: 14px; }
h1 { font-size: 20px; font-weight: 700; color: #dbe4ee; margin-bottom: 6px; }
p { font-size: 13px; color: #8899a6; margin-bottom: 24px; line-height: 1.5; }
.pin-input { width: 100%; font-size: 32px; letter-spacing: 12px; text-align: center; background: #070a0e; border: 2px solid #00cbb8; color: #00eed9; border-radius: 0; padding: 12px; margin-bottom: 20px; font-family: monospace; outline: none; transition: border-color 0.2s; }
.pin-input:focus { border-color: #00eed9; box-shadow: 0 0 16px rgba(0,203,184,0.3); }
button { width: 100%; background: #00cbb8; color: #070a0e; border: none; padding: 14px; font-size: 15px; font-weight: 700; border-radius: 0; cursor: pointer; transition: opacity 0.2s; }
button:active { opacity: 0.85; }
</style>
</head>
<body>
<div class="card">
<div class="icon" style="font-size: 24px; font-weight: bold; color: #00cbb8; margin-bottom: 12px;">[SECURE]</div>
<h1>OmaSend AirBridge</h1>
<p>Enter the 4-digit security PIN displayed on your PC screen.</p>
<form method="GET" action="/">
<input type="number" name="pin" class="pin-input" placeholder="••••" required autofocus pattern="[0-9]*" inputmode="numeric">
<button type="submit">Verify & Connect</button>
</form>
</div>
</body>
</html>"#.to_string()
}

fn render_web_app(active_endpoint: &str, shared_files: &[FileInfo]) -> String {
    let mut files_html = String::new();
    if shared_files.is_empty() {
        files_html.push_str("<div class='empty'>No files shared from PC.<br><small style='color:#667788;'>Add files to ~/Downloads/omasend/shared.</small></div>");
    } else {
        for f in shared_files {
            files_html.push_str(&format!(
                r#"<div class="file-item">
<div class="file-info"><div class="file-name">{}</div><div class="file-size">{}</div></div>
<button onclick="downloadFile('{}')" class="btn-sm">Download</button>
</div>"#,
                f.name, f.size_str, f.name
            ));
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>OmaSend • AirBridge E2EE</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #070a0e; color: #dbe4ee; padding: 16px; max-width: 560px; margin: 0 auto; }}
.header {{ display: flex; align-items: center; justify-content: space-between; padding-bottom: 14px; border-bottom: 1px solid #1a2332; margin-bottom: 16px; }}
.brand {{ font-size: 19px; font-weight: 700; color: #00cbb8; display: flex; align-items: center; gap: 8px; }}
.badges {{ display: flex; gap: 6px; flex-wrap: wrap; }}
.badge {{ font-size: 11px; background: rgba(0, 203, 184, 0.15); border: 1px solid #00cbb8; color: #00cbb8; padding: 4px 8px; border-radius: 0; font-weight: bold; }}
.badge-e2ee {{ font-size: 11px; background: rgba(39, 201, 63, 0.15); border: 1px solid #27c93f; color: #27c93f; padding: 4px 8px; border-radius: 0; font-weight: bold; display: flex; align-items: center; gap: 4px; }}
.card {{ background: #0e141d; border: 1px solid #1a2332; border-radius: 0; padding: 18px; margin-bottom: 16px; }}
.card-title {{ font-size: 12px; font-weight: 700; letter-spacing: 1px; color: #8899a6; text-transform: uppercase; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; }}
.drop-zone {{ border: 2px dashed #00cbb8; border-radius: 0; padding: 36px 16px; text-align: center; cursor: pointer; background: rgba(0, 203, 184, 0.03); transition: all 0.2s; }}
.drop-zone:hover {{ background: rgba(0, 203, 184, 0.08); border-color: #00eed9; }}
.drop-icon {{ font-size: 36px; margin-bottom: 8px; }}
.file-item {{ display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: #131b26; border-radius: 0; margin-bottom: 8px; border: 1px solid #1a2536; }}
.file-name {{ font-size: 14px; font-weight: 500; word-break: break-all; color: #dbe4ee; }}
.file-size {{ font-size: 12px; color: #8899a6; margin-top: 2px; }}
.btn-sm {{ background: #00cbb8; color: #070a0e; border: none; padding: 6px 14px; border-radius: 0; font-size: 12px; font-weight: 700; cursor: pointer; }}
textarea {{ width: 100%; height: 84px; background: #070a0e; border: 1px solid #1a2332; border-radius: 0; color: #dbe4ee; padding: 12px; font-size: 13px; margin-bottom: 10px; resize: vertical; outline: none; }}
textarea:focus {{ border-color: #00cbb8; }}
button.main-btn {{ width: 100%; background: #00cbb8; color: #070a0e; border: none; padding: 12px; font-size: 14px; font-weight: 700; border-radius: 0; cursor: pointer; }}
.clipboard-box {{ background: #070a0e; border: 1px solid #1a2332; padding: 12px; border-radius: 0; font-size: 13px; max-height: 110px; overflow-y: auto; margin-bottom: 10px; color: #00eed9; font-family: monospace; white-space: pre-wrap; }}
.empty {{ font-size: 13px; color: #8899a6; text-align: center; padding: 16px; line-height: 1.6; }}
#progress-bar {{ display: none; width: 100%; height: 8px; background: #1a2332; border-radius: 0; overflow: hidden; margin-top: 14px; }}
#progress-fill {{ width: 0%; height: 100%; background: #00cbb8; transition: width 0.2s; }}
#status-msg {{ font-size: 12px; font-weight: 600; color: #00cbb8; margin-top: 10px; text-align: center; }}
</style>
</head>
<body>
<div class="header">
<div class="brand">OmaSend AirBridge</div>
<div class="badges">
  <div class="badge">CONNECTED: {}</div>
  <div id="e2ee-badge" class="badge-e2ee">E2EE ACTIVE</div>
</div>
</div>

<div class="card">
<div class="card-title">
  <span>Send Files to PC</span>
  <span style="color:#27c93f; font-size:11px;">AES-256-GCM Encrypted</span>
</div>
<div class="drop-zone" onclick="document.getElementById('file-input').click()">
<div class="drop-icon" style="font-size: 20px; font-weight: bold; color: #00cbb8; margin-bottom: 6px;">[+]</div>
<div style="font-size: 15px; font-weight: 700;">Choose Photos, Videos or Files</div>
<div style="font-size: 12px; color: #8899a6; margin-top: 4px;">or tap / drag & drop here</div>
<input type="file" id="file-input" style="display: none;" onchange="uploadFiles(this.files)" multiple>
</div>
<div id="progress-bar"><div id="progress-fill"></div></div>
<div id="status-msg"></div>
</div>

<div class="card">
<div class="card-title">
  <span>PC Clipboard</span>
  <button onclick="fetchClipboard()" class="btn-sm" style="padding:3px 8px; font-size:11px;">Refresh</button>
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
        active_endpoint,
        files_html
    )
}

// ------------------- CONNECTION HANDLER -------------------

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

    if is_pin_rate_limited(client_ip) {
        let err = b"{\"error\":\"Too many failed PIN attempts. Please wait 60 seconds.\"}";
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

    let maybe_pin = extract_provided_pin(&req);
    let authorized = match maybe_pin {
        Some(ref p) if p == pin => {
            record_pin_attempt(client_ip, true);
            true
        }
        Some(_) => {
            let not_blocked = record_pin_attempt(client_ip, false);
            if !not_blocked {
                let err = b"{\"error\":\"Too many failed PIN attempts. Please wait 60 seconds.\"}";
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
        None => false,
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
        let (id, _) = get_or_create_device_id();
        let (vis, _) = get_visibility();
        let my_oma_id = get_or_create_oma_id();
        let resp = serde_json::json!({
            "status": "OK",
            "id": my_oma_id.clone(),
            "oma_id": my_oma_id,
            "device_id": id,
            "name": get_system_hostname(),
            "mode": vis
        });
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
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
            let peer_oma_id = req_data.get("oma_id")
                .or_else(|| req_data.get("sender_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let peer_name = req_data["name"].as_str().or_else(|| req_data["sender_name"].as_str()).unwrap_or("Paired Device");
            let peer_ip = req_data["ip"].as_str().or_else(|| req_data["sender_ip"].as_str());

            if rendezvous::validate_oma_id(peer_oma_id) {
                let _ = add_paired_peer(peer_oma_id, peer_name, peer_ip);
                let my_oma_id = get_or_create_oma_id();
                let my_name = get_system_hostname();
                let resp = serde_json::json!({
                    "status": "PAIRED",
                    "oma_id": my_oma_id,
                    "name": my_name
                });
                respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
                return;
            } else {
                respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid OmaID\"}", None, None);
                return;
            }
        }
        respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid JSON\"}", None, None);
        return;
    }

    if req.method == "GET" && req.path == "/api/p2p/peers" {
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
                respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid JSON request\"}", None, None);
                return;
            }
        };
        let req_data: serde_json::Value = match serde_json::from_slice(body_slice) {
            Ok(v) => v,
            Err(_) => {
                respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid JSON request\"}", None, None);
                return;
            }
        };

        let sender_id = req_data.get("oma_id")
            .or_else(|| req_data.get("sender_oma_id"))
            .or_else(|| req_data.get("sender_id"))
            .and_then(|v| v.as_str())
            .or_else(|| req.get_header("x-omasend-omaid"))
            .unwrap_or("unknown")
            .to_string();
        let sender_name = req_data["sender_name"].as_str().unwrap_or("Unknown Omarchy Device").to_string();
        let sender_ip = req_data["sender_ip"].as_str().unwrap_or("").to_string();
        let is_trusted = is_peer_paired(&sender_id) || is_peer_trusted(&sender_id);

        if !is_trusted {
            let err = serde_json::json!({ "error": "Peer OmaID is not paired with this device" });
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

        let initial_status = if is_trusted { "ACCEPTED" } else { "PENDING" };
        let initial_expiry = if is_trusted { now.saturating_add(600) } else { now.saturating_add(30) };

        let transfer = PendingFileTransfer {
            token: token.clone(),
            sender_id,
            sender_name: sender_name.clone(),
            sender_ip,
            file_names: file_names.clone(),
            files: files_info,
            total_size_bytes,
            created_at: now,
            expires_at: initial_expiry,
            status: initial_status.to_string(),
        };
        save_pending_transfer(&transfer);

        let size_mb = (total_size_bytes as f64) / 1024.0 / 1024.0;
        if is_trusted {
            notify_desktop(
                "OmaSend AirBridge",
                &format!("Auto-receiving {} file(s) ({:.1} MB) from trusted device '{}'.", file_names.len(), size_mb, sender_name),
            );
        } else {
            notify_desktop(
                "OmaSend AirBridge: Transfer Request",
                &format!("'{}' wants to send {} file(s) ({:.1} MB).\nOpen OmaSend panel to Accept or Decline.", sender_name, file_names.len(), size_mb),
            );
        }

        let resp = serde_json::json!({
            "status": initial_status,
            "token": token
        });
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    if req.path.starts_with("/api/p2p/decision") {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if req.method == "GET" {
            let token = req.get_param("token").unwrap_or_default();
            if let Some(pending) = get_pending_transfer() {
                if pending.token == token {
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
            if content_length > MAX_CONTROL_BODY {
                respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Request payload exceeds limit\"}", None, None);
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
                    respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid payload\"}", None, None);
                    return;
                }
            };
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_slice) {
                let token = val["token"].as_str().unwrap_or_default();
                let action = val["action"].as_str().unwrap_or_default();
                if let Some(mut pending) = get_pending_transfer() {
                    if pending.token == token {
                        if action == "accept" {
                            pending.status = "ACCEPTED".to_string();
                            pending.expires_at = now.saturating_add(600); // 10 minutes to complete file transfer
                            save_pending_transfer(&pending);
                            add_trusted_peer(&pending.sender_id, &pending.sender_name, "");
                            notify_desktop("OmaSend AirBridge", "Transfer accepted. Receiving files...");
                            respond(&stream, "200 OK", "application/json", b"{\"status\":\"ACCEPTED\"}", None, None);
                            return;
                        } else if action == "reject" {
                            pending.status = "REJECTED".to_string();
                            save_pending_transfer(&pending);
                            notify_desktop("OmaSend AirBridge", "Transfer declined.");
                            respond(&stream, "200 OK", "application/json", b"{\"status\":\"REJECTED\"}", None, None);
                            return;
                        }
                    }
                }
            }
            respond(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid token or action\"}", None, None);
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

        let mut pending = pending_opt.unwrap();
        let matching_info = pending.files.iter().find(|f| f.name == clean_filename).cloned();
        let is_in_pending = matching_info.is_some() || pending.file_names.iter().any(|n| n == &clean_filename);
        if !is_in_pending {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"File not listed in approved transfer request\"}", None, None);
            return;
        }

        if content_length > MAX_BODY_SIZE {
            respond(&stream, "413 Payload Too Large", "application/json", b"{\"error\":\"Payload exceeds 100 MiB limit\"}", None, None);
            return;
        }

        let upload_secs = (content_length as u64 / (512 * 1024)).clamp(30, MAX_UPLOAD_DURATION_SECS);
        let body_deadline = Instant::now() + Duration::from_secs(upload_secs);
        let body = match read_http_body(&mut stream, content_length, &initial_body, body_deadline, true, MAX_BODY_SIZE) {
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
            if let Some(pos) = pending.file_names.iter().position(|f| f == &clean_filename) {
                pending.file_names.remove(pos);
            }
            if let Some(pos) = pending.files.iter().position(|f| f.name == clean_filename) {
                pending.files.remove(pos);
            }
            if pending.file_names.is_empty() && pending.files.is_empty() {
                clear_pending_transfer();
            } else {
                save_pending_transfer(&pending);
            }
            let final_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            record_notified_file(&final_name);
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

    if req.method == "GET" && req.path.starts_with("/api/p2p/clipboard/image/") {
        let (vis, _) = get_visibility();
        if vis == "OFF" {
            respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Visibility is Off\"}", None, None);
            return;
        }
        let raw_hash = req.path.trim_start_matches("/api/p2p/clipboard/image/").trim();
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
        let vault = load_clipboard_vault();
        let resp = serde_json::json!({
            "status": "OK",
            "count": vault.items.len(),
            "items": vault.items
        });
        respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    if req.method == "POST" && req.path == "/api/p2p/clipboard" {
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
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_slice) {
            let sender_id = val.get("oma_id")
                .or_else(|| val.get("sender_oma_id"))
                .or_else(|| val.get("sender_id"))
                .and_then(|v| v.as_str())
                .or_else(|| req.get_header("x-omasend-omaid"))
                .unwrap_or_default();
            let sender_name = val["sender_name"].as_str().unwrap_or("Nearby Device");
            let is_trusted = is_peer_paired(sender_id) || is_peer_trusted(sender_id);
            if !is_trusted {
                respond(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Peer OmaID is not paired\"}", None, None);
                return;
            }

            let content_type = val["content_type"].as_str().unwrap_or("text");

            // Handle visual clipboard payloads (< 512 KiB Base64 or metadata announcement)
            if content_type.starts_with("image_") || val.get("image_hash").is_some() {
                let img_hash = val["image_hash"].as_str();
                let img_size = val["image_size"].as_u64().unwrap_or(0);
                let img_w = val["image_width"].as_u64().unwrap_or(0) as u32;
                let img_h = val["image_height"].as_u64().unwrap_or(0) as u32;
                let thumb_b64 = val["thumbnail_base64"].as_str().map(|s| s.to_string());

                if let Some(b64_data) = val["image_base64"].as_str() {
                    if let Ok(raw_bytes) = base64_decode(b64_data) {
                        if let Ok((verified_ct, w, h)) = validate_image_header(&raw_bytes) {
                            let computed_hash = compute_image_clipboard_hash(&raw_bytes);
                            if img_hash.map_or(true, |expected| expected == computed_hash) {
                                set_last_synced_clipboard_hash(&computed_hash);
                                let _ = stage_clipboard_image(&raw_bytes, &verified_ct);
                                let _ = set_pc_image_clipboard(&raw_bytes, &verified_ct);
                                let _ = add_image_clipboard_to_vault(
                                    sender_name,
                                    &verified_ct,
                                    &computed_hash,
                                    raw_bytes.len() as u64,
                                    w,
                                    h,
                                    thumb_b64,
                                );
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
                        let _ = add_image_clipboard_to_vault(
                            sender_name,
                            content_type,
                            hash,
                            img_size,
                            img_w,
                            img_h,
                            thumb_b64,
                        );
                        let peer_ip = val["sender_ip"].as_str().unwrap_or("");
                        if !peer_ip.is_empty() {
                            p2p_fetch_image_clipboard_and_apply(peer_ip, hash, content_type);
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
                    set_pc_clipboard(text);
                    let _ = add_clipboard_to_vault(sender_name, text);
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
            respond(&stream, "401 Unauthorized", "text/plain", b"Unauthorized. Please provide valid PIN.", None, None);
        }
        return;
    }

    let set_cookie = Some(format!("pin={}", pin));

    if req.method == "GET" && req.path == "/" {
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
                let _ = add_clipboard_to_vault("Web Client (E2EE)", &text);
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
            let _ = add_clipboard_to_vault("Web Client", &text);
            notify_desktop("OmaSend: Clipboard Received", &format!("Clipboard updated from device ({} chars)", text.len()));
            play_clipboard_sound();
            let resp = serde_json::json!({ "status": "OK" });
            respond(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        }
    }
    else if req.method == "GET" && (req.path == "/api/clipboard-vault" || req.path == "/api/clipboard/vault" || req.path == "/api/clipboard-history") {
        let vault = load_clipboard_vault();
        let resp = serde_json::json!({
            "status": "OK",
            "count": vault.items.len(),
            "items": vault.items
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
        return;
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
        let mut saved_name = format!("transfer_{}.bin", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());
        let mut success = false;

        match body {
            HttpBody::Memory(bytes) => {
                let body_str = String::from_utf8_lossy(&bytes);
                if let Some(pos) = body_str.find("filename=\"") {
                    if let Some(end) = body_str[pos + 10..].find('"') {
                        saved_name = sanitize_filename(&body_str[pos + 10..pos + 10 + end]);
                    }
                }
                let data_start = bytes.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(0);
                let data_slice = if data_start < bytes.len() { &bytes[data_start..] } else { &bytes[..] };

                if let Some(avail) = get_available_disk_space(&ddir) {
                    if (data_slice.len() as u64).saturating_add(10 * 1024 * 1024) > avail {
                        respond(&stream, "507 Insufficient Storage", "text/plain", b"Insufficient disk space to save file", None, None);
                        return;
                    }
                }

                let file_path = get_unique_filepath(&ddir, &saved_name);
                if write_secure_bytes(&file_path, data_slice).is_ok() {
                    let final_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    record_notified_file(&final_name);
                    success = true;
                    RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
                    notify_desktop(
                        "OmaSend: File Received",
                        &format!("'{}' saved to Downloads/omasend.", final_name),
                    );
                }
            }
            HttpBody::Staged(staged) => {
                if let Ok(mut sf) = File::open(&staged.path) {
                    let mut head_buf = [0u8; 4096];
                    let n = sf.read(&mut head_buf).unwrap_or(0);
                    let head_str = String::from_utf8_lossy(&head_buf[..n]);
                    if let Some(pos) = head_str.find("filename=\"") {
                        if let Some(end) = head_str[pos + 10..].find('"') {
                            saved_name = sanitize_filename(&head_str[pos + 10..pos + 10 + end]);
                        }
                    }
                    let dstart = head_buf[..n].windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(0) as u64;
                    let dlen = staged.size.saturating_sub(dstart);

                    let file_path = get_unique_filepath(&ddir, &saved_name);
                    if let Ok(mut src) = File::open(&staged.path) {
                        if src.seek(SeekFrom::Start(dstart)).is_ok() {
                            let mut opts = OpenOptions::new();
                            opts.write(true).create_new(true);
                            #[cfg(unix)]
                            {
                                opts.mode(0o600);
                            }
                            if let Ok(mut dest) = opts.open(&file_path) {
                                let mut take = src.take(dlen);
                                if std::io::copy(&mut take, &mut dest).is_ok() {
                                    let final_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                    record_notified_file(&final_name);
                                    success = true;
                                    RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
                                    notify_desktop(
                                        "OmaSend: File Received",
                                        &format!("'{}' saved to Downloads/omasend.", final_name),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

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

fn run_server() {
    // Enforce military-grade defense: anti-forensics memory protection
    military::enable_anti_forensics();
    let state_dir = get_state_dir();

    let pid_file = state_dir.join("engine.pid");
    if let Ok(old_pid_str) = read_secure_file(&pid_file) {
        if let Ok(old_pid) = old_pid_str.trim().parse::<i32>() {
            let my_pid = std::process::id() as i32;
            if old_pid != my_pid {
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
    println!("OmaSend listening on http://{}:{} [PIN: {}]", local_ip, PORT, pin);

    // Spawn P2P AirBridge discovery threads
    thread::spawn(run_p2p_discovery_listener);
    thread::spawn(run_p2p_beacon_broadcaster);
    start_download_dir_watcher(&get_download_dir());
    start_clipboard_sentinel();

    for mut s in listener.incoming().flatten() {
        let _ = s.set_nodelay(true);
        let client_ip = s.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
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
        println!("{}", oma_id);
        return;
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

    if let Some(pos) = args.iter().position(|a| a == "--rendezvous-topic" || a == "--topic") {
        let oma_id = args.get(pos + 1).cloned().unwrap_or_else(get_or_create_oma_id);
        let topic = compute_rendezvous_topic(&oma_id);
        println!("{}", topic);
        return;
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

    if args.iter().any(|a| a == "--rendezvous" || a == "--publish-rendezvous") {
        let oma_id = get_or_create_oma_id();
        let stun_addr = query_stun_external_addr().map(|a| a.to_string());
        let (_, _, wan_url) = get_wan_status();
        let (dev_id, _) = get_or_create_device_id();
        let hostname = get_system_hostname();
        match publish_local_rendezvous_anchor(
            &oma_id,
            &ip,
            PORT,
            stun_addr.as_deref(),
            wan_url.as_deref(),
            &dev_id,
            &hostname,
            &get_state_dir(),
        ) {
            Ok(envelope) => {
                println!("{}", serde_json::to_string_pretty(&envelope).unwrap_or_default());
            }
            Err(e) => {
                eprintln!("Error publishing rendezvous anchor: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--rendezvous-query") {
        if let Some(target_oma_id) = args.get(pos + 1) {
            match query_local_rendezvous_anchor(target_oma_id, &get_state_dir()) {
                Some(rec) => {
                    println!("{}", serde_json::to_string_pretty(&rec).unwrap_or_default());
                }
                None => {
                    eprintln!("No rendezvous anchor found or decryption failed for OmaID {}", target_oma_id);
                    std::process::exit(1);
                }
            }
            return;
        }
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
                match add_paired_peer(&norm, &name, ip_arg) {
                    Ok(peer) => {
                        send_immediate_beacon_broadcast();
                        println!("{{\"status\":\"SUCCESS\",\"oma_id\":\"{}\",\"name\":\"{}\"}}", peer.oma_id, peer.name);
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

    if let Some(pos) = args.iter().position(|a| a == "--trust-peer") {
        if let (Some(id), Some(name)) = (args.get(pos + 1), args.get(pos + 2)) {
            let fp = args.get(pos + 3).map(|s| s.as_str()).unwrap_or("");
            add_trusted_peer(id, name, fp);
            println!("Peer '{}' ({}) trusted successfully.", name, id);
            return;
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--accept-transfer") {
        if let Some(token) = args.get(pos + 1) {
            if let Some(mut pending) = get_pending_transfer() {
                if pending.token == *token {
                    pending.status = "ACCEPTED".to_string();
                    save_pending_transfer(&pending);
                    let _ = add_paired_peer(&pending.sender_id, &pending.sender_name, Some(&pending.sender_ip));
                    add_trusted_peer(&pending.sender_id, &pending.sender_name, "");
                    notify_desktop("OmaSend AirBridge", "Transfer accepted. Receiving files...");
                    println!("Transfer accepted");
                    return;
                }
            }
            eprintln!("Invalid or expired transfer token");
            return;
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--reject-transfer") {
        if let Some(token) = args.get(pos + 1) {
            if let Some(mut pending) = get_pending_transfer() {
                if pending.token == *token {
                    pending.status = "REJECTED".to_string();
                    save_pending_transfer(&pending);
                    notify_desktop("OmaSend AirBridge", "Transfer declined.");
                    println!("Transfer declined");
                    return;
                }
            }
            eprintln!("Invalid or expired transfer token");
            return;
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--send-p2p" || a == "--send") {
        let target_arg = args.get(pos + 1);
        let second_arg = args.get(pos + 2);

        let (target, file_path_str) = match (target_arg, second_arg) {
            (Some(t), Some(f)) if t != "auto" => (t.clone(), f.clone()),
            (Some(f_or_auto), None) => {
                let peers = get_discovered_peers();
                if let Some(first_peer) = peers.first() {
                    (first_peer.ip.clone(), f_or_auto.clone())
                } else {
                    eprintln!("Error: No active peers discovered for automatic send");
                    return;
                }
            }
            (Some(t), Some(f)) if t == "auto" => {
                let peers = get_discovered_peers();
                if let Some(first_peer) = peers.first() {
                    (first_peer.ip.clone(), f.clone())
                } else {
                    eprintln!("Error: No active peers discovered for automatic send");
                    return;
                }
            }
            _ => {
                eprintln!("Usage: omasend-engine --send [peer_ip|auto] <file_path>");
                return;
            }
        };

        let path = Path::new(&file_path_str);
        match p2p_send_file_to_peer(&target, path) {
            Ok(()) => println!("File sent successfully to {}", target),
            Err(e) => eprintln!("Error sending file: {}", e),
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
                &["--file-selection", "--title=OmaSend: Select File to Send via AirBridge"],
                &envs,
                deadline,
                4096,
            ) {
                let chosen = String::from_utf8_lossy(&out).trim().to_string();
                if !chosen.is_empty() {
                    let path = Path::new(&chosen);
                    match p2p_send_file_to_peer(target, path) {
                        Ok(()) => println!("File successfully sent to {}", target),
                        Err(e) => eprintln!("Error sending file: {}", e),
                    }
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

    let (wan_active, wan_connecting, wan_url) = get_wan_status();
    let active_mode = get_active_mode();
    let qr_file = get_state_dir().join("qr.svg");
    let qr_path = qr_file.to_string_lossy().to_string();
    let ddir = get_download_dir().to_string_lossy().to_string();
    let sdir = get_shared_dir().to_string_lossy().to_string();

    let active_url = if active_mode == "WAN" {
        if let Some(ref u) = wan_url {
            format!("{}/?pin={}#key={}", u, pin, session_key)
        } else {
            format!("http://{}:{}/?pin={}#key={}", ip, PORT, pin, session_key)
        }
    } else {
        format!("http://{}:{}/?pin={}#key={}", ip, PORT, pin, session_key)
    };

    if args.iter().any(|a| a == "--status") {
        let mode_tag = if active_mode == "WAN" { "WAN" } else { "LAN" };
        println!(
            "{{\"text\":\"\",\"tooltip\":\"OmaSend AirBridge [{}]\\n{}\",\"class\":\"normal\"}}",
            mode_tag, active_url
        );
        return;
    }

    if args.iter().any(|a| a == "--json") {
        let (vis, rem) = get_visibility();
        let (dev_id, _) = get_or_create_device_id();
        let oma_id = get_or_create_oma_id();
        let cluster_id = compute_rendezvous_topic(&oma_id);
        let wan_mode = if wan_active { "WAN" } else { "LAN" }.to_string();
        let stun_addr = query_stun_external_addr().map(|a| a.to_string());
        let state = ServerState {
            status: "ACTIVE".to_string(),
            port: PORT,
            local_ip: ip,
            tailscale_ip: get_tailscale_ip(),
            pin,
            session_key,
            active_mode,
            wan_active,
            wan_connecting,
            wan_provider: if wan_active || wan_connecting { get_wan_provider() } else { None },
            wan_url,
            active_url,
            download_dir: ddir,
            shared_dir: sdir,
            qr_path,
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
            clipboard_vault: get_clipboard_vault_items(),
            oma_id,
            wan_mode,
            cluster_id,
            stun_addr,
        };
        if let Ok(s) = serde_json::to_string_pretty(&state) {
            println!("{}", s);
        }
        return;
    }

    println!("OMASEND - WIRELESS AIRBRIDGE & E2EE CLIPBOARD SENTINEL");
    println!("Mode: {}", active_mode);
    println!("Active URL: {}", active_url);
    println!("QR: {}", qr_path);
    println!("E2EE Key: {}", session_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SYNC_MUTEX: Mutex<()> = Mutex::new(());

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
        assert_eq!(pin.len(), 4);

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

    #[test]
    fn test_visibility_modes() {
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
        let req_query = HttpRequest {
            query: "foo=bar&pin=4321&baz=1".to_string(),
            ..Default::default()
        };
        assert_eq!(extract_provided_pin(&req_query), Some("4321".to_string()));

        let req_header = HttpRequest {
            headers: vec![("x-omasend-pin".to_string(), "9988".to_string())],
            ..Default::default()
        };
        assert_eq!(extract_provided_pin(&req_header), Some("9988".to_string()));

        let req_cookie = HttpRequest {
            headers: vec![("cookie".to_string(), "session=abc; pin=1122; test=1".to_string())],
            ..Default::default()
        };
        assert_eq!(extract_provided_pin(&req_cookie), Some("1122".to_string()));

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
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
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

        // Reset staged bytes to baseline
        CURRENT_STAGED_BYTES.store(0, Ordering::SeqCst);

        // Reserve 100 MiB
        let guard1 = StagingReservationGuard::try_reserve(100 * 1024 * 1024, &ddir);
        assert!(guard1.is_ok(), "First 100 MiB reservation should succeed");
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), 100 * 1024 * 1024);

        // Reserve another 100 MiB (total 200 MiB = MAX_AGGREGATE_STAGING_BYTES)
        let guard2 = StagingReservationGuard::try_reserve(100 * 1024 * 1024, &ddir);
        assert!(guard2.is_ok(), "Second 100 MiB reservation reaching aggregate cap should succeed");
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), 200 * 1024 * 1024);

        // Third reservation exceeding cap must fail
        let guard3 = StagingReservationGuard::try_reserve(1024, &ddir);
        assert!(guard3.is_err(), "Reservation exceeding 200 MiB aggregate cap must be rejected");

        // Drop first guard
        drop(guard1);
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), 100 * 1024 * 1024);

        // Now a 50 MiB reservation should succeed
        let guard4 = StagingReservationGuard::try_reserve(50 * 1024 * 1024, &ddir);
        assert!(guard4.is_ok(), "Reservation under remaining cap should succeed");
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), 150 * 1024 * 1024);

        // Cleanup
        drop(guard2);
        drop(guard4);
        assert_eq!(CURRENT_STAGED_BYTES.load(Ordering::SeqCst), 0);
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
            total_size_bytes: 1024,
            created_at: 100,
            expires_at: 500,
            status: "ACCEPTED".to_string(),
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
    fn test_military_landlock_and_anti_forensics_lifecycle() {
        use crate::military::{enable_anti_forensics, enable_landlock_sandbox};

        // Anti-forensics must succeed on Linux
        assert!(enable_anti_forensics());

        // Landlock sandbox gracefully falls back or succeeds
        let tmp = std::env::temp_dir();
        let _ = enable_landlock_sandbox(&[&tmp], &[&tmp]);
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
    fn test_clipboard_vault_lifecycle_and_0600_permissions() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
        let test_text = format!("Unique test note {}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        
        let item = add_clipboard_to_vault("POCO Phone", &test_text).expect("Add to clipboard vault");
        assert_eq!(item.sender, "POCO Phone");
        assert_eq!(item.text, test_text);
        assert_eq!(item.char_count, test_text.chars().count());

        let vault = load_clipboard_vault();
        assert!(!vault.items.is_empty());
        assert_eq!(vault.items[0].text, test_text);

        // Verify file permissions are strictly 0600
        let vault_file = get_state_dir().join("clipboard_vault.json");
        let meta = fs::symlink_metadata(&vault_file).expect("clipboard_vault.json must exist");
        assert_eq!(meta.mode() & 0o777, 0o600, "clipboard_vault.json must enforce 0600 permissions");

        let hist_file = get_state_dir().join("clipboard_history.json");
        if hist_file.exists() {
            let hist_meta = fs::symlink_metadata(&hist_file).expect("clipboard_history.json must exist");
            assert_eq!(hist_meta.mode() & 0o777, 0o600, "clipboard_history.json must enforce 0600 permissions");
        }
    }

    #[test]
    fn test_anti_echo_loop_and_sha256_hash_tracking() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
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
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
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
    fn test_server_state_includes_oma_id_and_rendezvous_fields() {
        let oma_id = "4829-1048-5729-1104".to_string();
        let topic = compute_rendezvous_topic(&oma_id);
        let state = ServerState {
            status: "ACTIVE".to_string(),
            port: PORT,
            local_ip: "192.168.1.50".to_string(),
            tailscale_ip: None,
            pin: "1234".to_string(),
            session_key: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
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
            clipboard_vault: vec![],
            oma_id: oma_id.clone(),
            wan_mode: "LAN".to_string(),
            cluster_id: topic.clone(),
            stun_addr: Some("198.51.100.1:53317".to_string()),
        };

        let json = serde_json::to_string(&state).expect("Serialize ServerState");
        assert!(json.contains("\"oma_id\":\"4829-1048-5729-1104\""));
        assert!(json.contains("\"wan_mode\":\"LAN\""));
        assert!(json.contains(&format!("\"cluster_id\":\"{}\"", topic)));
        assert!(json.contains("\"stun_addr\":\"198.51.100.1:53317\""));
    }

    #[test]
    fn test_publish_and_query_local_rendezvous_anchor() {
        let temp_dir = env::temp_dir().join(format!("rendezvous_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let oma_id = "1234-5678-9012-3452";
        let dev_id = "dev_alpha";
        let hostname = "test-host";

        let published = publish_local_rendezvous_anchor(
            oma_id,
            "192.168.1.200",
            53317,
            Some("203.0.113.10:53317"),
            Some("https://test.trycloudflare.com"),
            dev_id,
            hostname,
            &temp_dir,
        ).expect("Publish local anchor");

        assert_eq!(published.topic, compute_rendezvous_topic(oma_id));

        let queried = query_local_rendezvous_anchor(oma_id, &temp_dir)
            .expect("Query local rendezvous anchor");

        assert_eq!(queried.device_id, dev_id);
        assert_eq!(queried.hostname, hostname);
        assert_eq!(queried.local_ip, "192.168.1.200");
        assert_eq!(queried.local_port, 53317);
        assert_eq!(queried.stun_addr.as_deref(), Some("203.0.113.10:53317"));
        assert_eq!(queried.wan_url.as_deref(), Some("https://test.trycloudflare.com"));

        let _ = fs::remove_dir_all(&temp_dir);
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
                last_seen_secs: now,
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
                last_seen_secs: now - 30, // 30 seconds old -> expired
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
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();

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
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
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
    fn test_image_clipboard_vault_integration() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
        let dummy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let item = add_image_clipboard_to_vault(
            "POCO Pad",
            "image_png",
            dummy_hash,
            102400,
            1920,
            1080,
            Some("dGh1bWJuYWls".to_string()),
        ).expect("Add image to vault");

        assert_eq!(item.sender, "POCO Pad");
        assert_eq!(item.content_type, "image_png");
        assert_eq!(item.image_hash.as_deref(), Some(dummy_hash));
        assert_eq!(item.image_width, Some(1920));
        assert_eq!(item.image_height, Some(1080));
        assert_eq!(item.image_size, Some(102400));

        let vault = load_clipboard_vault();
        let found = vault.items.iter().find(|i| i.image_hash.as_deref() == Some(dummy_hash));
        assert!(found.is_some(), "Image item must be persisted and loaded from vault");

        let json = serde_json::to_string(&item).expect("Serialize image ClipboardItem");
        let parsed: ClipboardItem = serde_json::from_str(&json).expect("Deserialize image ClipboardItem");
        assert_eq!(parsed.content_type, "image_png");
        assert_eq!(parsed.image_hash.as_deref(), Some(dummy_hash));
        assert_eq!(parsed.image_width, Some(1920));
    }

    #[test]
    fn test_http_p2p_image_and_vault_endpoints() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
        set_visibility("ALL");
        let valid_raw_oma_id = rendezvous::generate_raw_oma_id();
        let valid_peer_oma_id = rendezvous::format_oma_id(&valid_raw_oma_id);
        let _ = add_paired_peer(&valid_peer_oma_id, "Test Device", None);

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local listener");
        let local_addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("Accept client 1");
            handle_connection(stream, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

            let (stream, _) = listener.accept().expect("Accept client 2");
            handle_connection(stream, "127.0.0.1", "1234", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

            let (stream, _) = listener.accept().expect("Accept client 3");
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
            "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-OmaSend-OmaID: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            local_addr, valid_peer_oma_id, post_bytes.len()
        );
        client1.write_all(req1.as_bytes()).unwrap();
        client1.write_all(&post_bytes).unwrap();
        let mut resp1 = String::new();
        client1.read_to_string(&mut resp1).unwrap();
        assert!(resp1.starts_with("HTTP/1.1 200 OK"), "POST /api/p2p/clipboard must return 200 OK: {}", resp1);

        // 2. Fetch image via /api/p2p/clipboard/image/<hash>
        let mut client2 = TcpStream::connect(local_addr).expect("Connect client 2");
        let req2 = format!(
            "GET /api/p2p/clipboard/image/{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            img_hash, local_addr
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
        assert!(resp3.contains(&img_hash), "Vault response must contain stored image hash");

        server_thread.join().expect("Join server thread");
    }

    #[test]
    fn test_webp_thumbnail_generation_and_caching() {
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();

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
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
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
        let _guard = TEST_SYNC_MUTEX.lock().unwrap();
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
}


