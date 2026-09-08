mod subproc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use sha2::{Digest, Sha256};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subproc::{kill_process_group, run_cmd_bounded, run_cmd_write_stdin_bounded};

extern "C" {
    fn getuid() -> u32;
}

const PORT: u16 = 8844;
const P2P_BEACON_PORT: u16 = 8845;
static RECEIVED_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size_str: String,
    pub size_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredPeer {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub transport: String, // "LAN", "BT", or "HYBRID"
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingFileTransfer {
    pub token: String,
    pub sender_id: String,
    pub sender_name: String,
    pub sender_ip: String,
    pub file_names: Vec<String>,
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
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub mode: String,
    pub bt: bool,
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
    pub active_url: String,
    pub total_received: usize,
    pub recent_files: Vec<FileInfo>,
    pub shared_files: Vec<FileInfo>,
    // AirBridge P2P & Bluetooth
    pub p2p_device_id: String,
    pub p2p_hostname: String,
    pub p2p_visibility: String,
    pub p2p_visibility_remaining_secs: u64,
    pub p2p_bluetooth_available: bool,
    pub p2p_discovered_peers: Vec<DiscoveredPeer>,
    pub p2p_pending_transfer: Option<PendingFileTransfer>,
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

    Err("WAN Tunneling requires cloudflared. Please install the trusted system package: sudo pacman -S cloudflared (see README.md)".to_string())
}

// ------------------- QR CODE & URLS -------------------

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

    if qr_file.exists() {
        if let Ok(last_url) = read_secure_file(&last_qr_file) {
            if last_url.trim() == full_url {
                return; // Cached: URL has not changed
            }
        }
    }

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
    ];
    let mut envs = Vec::new();
    for k in keys {
        if let Ok(v) = env::var(k) {
            if !v.is_empty() {
                envs.push((k, v));
            }
        }
    }
    envs
}

fn notify_desktop(title: &str, body: &str) {
    let env_store = get_desktop_gui_envs();
    let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let deadline = Instant::now() + Duration::from_millis(1500);
    let _ = run_cmd_bounded(
        "/usr/bin/notify-send",
        &["-a", "OmaSend", "-i", "document-send", title, body],
        &envs,
        deadline,
        1024,
    );
}

fn get_pc_clipboard() -> String {
    let env_store = get_desktop_gui_envs();
    let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let deadline = Instant::now() + Duration::from_millis(600);
    if let Some(out) = run_cmd_bounded("/usr/bin/wl-paste", &["--no-newline"], &envs, deadline, 1024 * 1024) {
        return String::from_utf8_lossy(&out).to_string();
    }
    String::new()
}

fn set_pc_clipboard(text: &str) {
    let env_store = get_desktop_gui_envs();
    let envs: Vec<(&str, &str)> = env_store.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let deadline = Instant::now() + Duration::from_millis(800);
    let _ = run_cmd_write_stdin_bounded("/usr/bin/wl-copy", &[], &envs, text.as_bytes(), deadline);
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
    dir.join(format!("{}_{}", stem, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()))
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

// ------------------- P2P AIRDROP & BLUETOOTH MODULE -------------------

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
    let peers = load_trusted_peers();
    peers.iter().any(|p| p.id == peer_id)
}

fn add_trusted_peer(id: &str, name: &str, fingerprint: &str) {
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

fn is_bluetooth_available() -> bool {
    let deadline = Instant::now() + Duration::from_millis(400);
    if let Some(out) = run_cmd_bounded("/usr/bin/bluetoothctl", &["show"], &[], deadline, 4096) {
        let s = String::from_utf8_lossy(&out);
        return s.contains("Powered: yes");
    }
    false
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
    let path = get_state_dir().join("discovered_peers.json");
    if let Ok(content) = read_secure_file(&path) {
        if let Ok(peers) = serde_json::from_str::<Vec<DiscoveredPeer>>(&content) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            // Prune peers older than 15s
            return peers.into_iter().filter(|p| now.saturating_sub(p.last_seen_secs) <= 15).collect();
        }
    }
    Vec::new()
}

fn save_discovered_peers(peers: &[DiscoveredPeer]) {
    let path = get_state_dir().join("discovered_peers.json");
    if let Ok(s) = serde_json::to_string(peers) {
        let _ = write_secure_file(&path, &s);
    }
}

fn update_discovered_peer(packet: &P2pBeaconPacket) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (my_id, _) = get_or_create_device_id();
    if packet.id == my_id {
        return;
    }
    let (vis, _) = get_visibility();
    if vis == "OFF" {
        return;
    }
    let trusted = is_peer_trusted(&packet.id);
    if vis == "KNOWN" && !trusted && packet.mode != "EVERYONE" {
        return;
    }

    let transport = if packet.bt && is_bluetooth_available() {
        "HYBRID".to_string()
    } else {
        "LAN".to_string()
    };

    let mut peers = get_discovered_peers();
    if let Some(existing) = peers.iter_mut().find(|p| p.id == packet.id) {
        existing.name = packet.name.clone();
        existing.ip = packet.ip.clone();
        existing.port = packet.port;
        existing.transport = transport;
        existing.fingerprint = packet.fp.clone();
        existing.is_trusted = trusted;
        existing.last_seen_secs = now;
    } else {
        peers.push(DiscoveredPeer {
            id: packet.id.clone(),
            name: packet.name.clone(),
            ip: packet.ip.clone(),
            port: packet.port,
            transport,
            fingerprint: packet.fp.clone(),
            is_trusted: trusted,
            last_seen_secs: now,
        });
    }
    save_discovered_peers(&peers);
}

fn run_p2p_beacon_broadcaster() {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = socket.set_broadcast(true);

    loop {
        let (vis, _) = get_visibility();
        if vis != "OFF" {
            let (device_id, fp) = get_or_create_device_id();
            let hostname = get_system_hostname();
            let ip = get_local_ip();
            let bt = is_bluetooth_available();

            let packet = P2pBeaconPacket {
                magic: "OMASEND_P2P".to_string(),
                v: 1,
                id: device_id,
                name: hostname,
                ip: ip.clone(),
                port: PORT,
                mode: vis,
                bt,
                fp,
            };

            if let Ok(bytes) = serde_json::to_vec(&packet) {
                let _ = socket.send_to(&bytes, format!("255.255.255.255:{}", P2P_BEACON_PORT));
                // Also broadcast to local subnet
                if let Some(dot) = ip.rfind('.') {
                    let subnet_bcast = format!("{}.255:{}", &ip[..dot], P2P_BEACON_PORT);
                    let _ = socket.send_to(&bytes, subnet_bcast);
                }
                // Unicast directly to discovered peers to bypass Wi-Fi broadcast filtering
                for peer in get_discovered_peers() {
                    let _ = socket.send_to(&bytes, format!("{}:{}", peer.ip, P2P_BEACON_PORT));
                }
            }
        }
        thread::sleep(Duration::from_secs(3));
    }
}

fn run_p2p_discovery_listener() {
    let socket = match UdpSocket::bind(format!("0.0.0.0:{}", P2P_BEACON_PORT)) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut buf = [0u8; 2048];
    while let Ok((amt, _src)) = socket.recv_from(&mut buf) {
        if amt > 0 && amt <= 2048 {
            if let Ok(packet) = serde_json::from_slice::<P2pBeaconPacket>(&buf[..amt]) {
                if packet.magic == "OMASEND_P2P" {
                    update_discovered_peer(&packet);
                }
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
            let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(15)));
            return Ok(s);
        }
    }
    Err(format!(
        "Connection timed out to '{}'. Ensure port 8844 TCP is open in firewall (UFW).",
        addr_str
    ))
}

fn p2p_send_file_to_peer(target_ip: &str, file_path: &Path) -> Result<(), String> {
    let file_bytes = safe_read_file(file_path).map_err(|e| format!("Security check failed: {}", e))?;
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let size_bytes = file_bytes.len() as u64;

    let (my_id, _) = get_or_create_device_id();
    let my_name = get_system_hostname();

    // 1. Send transfer request
    let request_payload = serde_json::json!({
        "sender_id": my_id,
        "sender_name": my_name,
        "sender_ip": get_local_ip(),
        "files": [
            { "name": file_name, "size_bytes": size_bytes }
        ],
        "total_size_bytes": size_bytes
    });

    let addr = format!("{}:{}", target_ip, PORT);
    let mut stream = match connect_peer_with_timeout(&addr, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(e) => {
            notify_desktop(
                "OmaSend AirBridge",
                &format!("Connection failed to {}. Check firewall port 8844.", target_ip),
            );
            return Err(e);
        }
    };
    let req_bytes = request_payload.to_string().into_bytes();
    let http_req = format!(
        "POST /api/p2p/request HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr, req_bytes.len()
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

    println!("Peer accepted! Streaming file '{}' ({} bytes)...", file_name, size_bytes);

    // 3. Upload file
    let mut upload_stream = connect_peer_with_timeout(&addr, Duration::from_secs(6))
        .map_err(|e| format!("Failed to connect to peer for upload: {}", e))?;
    let encoded_filename = urlencoding_encode(&file_name);
    let upload_header = format!(
        "POST /api/p2p/upload?token={}&filename={} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        token, encoded_filename, addr, file_bytes.len()
    );
    upload_stream.write_all(upload_header.as_bytes()).map_err(|e| e.to_string())?;
    upload_stream.write_all(&file_bytes).map_err(|e| e.to_string())?;

    let mut final_resp = String::new();
    let _ = upload_stream.read_to_string(&mut final_resp);

    println!("Transfer successfully completed to {}!", target_ip);
    notify_desktop("OmaSend AirBridge", &format!("'{}' successfully sent to {}.", file_name, target_ip));
    Ok(())
}

fn p2p_sync_clipboard_to_peer(target_ip: &str) -> Result<(), String> {
    let text = get_pc_clipboard();
    if text.is_empty() {
        notify_desktop("OmaSend AirBridge", "Clipboard is empty. Copy some text first.");
        return Err("Clipboard is empty".to_string());
    }
    let (my_id, _) = get_or_create_device_id();
    let my_name = get_system_hostname();
    let payload = serde_json::json!({
        "sender_id": my_id,
        "sender_name": my_name,
        "text": text
    });
    let addr = format!("{}:{}", target_ip, PORT);
    let mut stream = match connect_peer_with_timeout(&addr, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(e) => {
            notify_desktop(
                "OmaSend AirBridge",
                &format!("Connection failed to {}. Check firewall port 8844.", target_ip),
            );
            return Err(e);
        }
    };
    let req_bytes = payload.to_string().into_bytes();
    let http_req = format!(
        "POST /api/p2p/clipboard HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr, req_bytes.len()
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

struct HttpRequest {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body_offset: usize,
}

impl HttpRequest {
    fn get_header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        for (k, v) in &self.headers {
            if k == &lower {
                return Some(v.as_str());
            }
        }
        None
    }

    fn get_param(&self, key: &str) -> Option<String> {
        let prefix = format!("{}=", key);
        for part in self.query.split('&') {
            if part.starts_with(&prefix) {
                return Some(part[prefix.len()..].to_string());
            }
        }
        None
    }
}

fn read_full_http_request(stream: &mut TcpStream) -> Option<(HttpRequest, Vec<u8>)> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));

    let mut buffer = Vec::with_capacity(65536);
    let mut temp = [0u8; 16384];
    let mut header_end = None;
    let mut content_length: usize = 0;
    const MAX_HEADER_SIZE: usize = 65536; // 64 KiB
    const MAX_BODY_SIZE: usize = 250 * 1024 * 1024; // 250 MiB limit for uploads

    loop {
        let n = match stream.read(&mut temp) {
            Ok(bytes) if bytes > 0 => bytes,
            _ => break,
        };
        buffer.extend_from_slice(&temp[..n]);

        if header_end.is_none() {
            if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(pos + 4);
                let header_str = String::from_utf8_lossy(&buffer[..pos]);
                for line in header_str.lines() {
                    if let Some(col) = line.find(':') {
                        let k = line[..col].trim().to_lowercase();
                        let v = line[col + 1..].trim();
                        if k == "content-length" {
                            content_length = v.parse::<usize>().unwrap_or(0);
                            if content_length > MAX_BODY_SIZE {
                                return None; // Reject oversized payload
                            }
                        }
                    }
                }
            } else if buffer.len() > MAX_HEADER_SIZE {
                return None; // Header overrun protection
            }
        }

        if let Some(hend) = header_end {
            if buffer.len() >= hend.saturating_add(content_length) {
                break;
            }
        }
    }

    let hend = header_end?;
    let header_str = String::from_utf8_lossy(&buffer[..hend - 4]);
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

    Some((
        HttpRequest {
            method,
            path,
            query,
            headers,
            body_offset: hend,
        },
        buffer,
    ))
}

fn is_authorized(req: &HttpRequest, pin: &str) -> bool {
    for part in req.query.split('&') {
        if let Some(val) = part.strip_prefix("pin=") {
            if val == pin {
                return true;
            }
        }
    }
    if let Some(h) = req.get_header("x-omasend-pin") {
        if h == pin {
            return true;
        }
    }
    if let Some(cookie_val) = req.get_header("cookie") {
        for c in cookie_val.split(';') {
            let ct = c.trim();
            if let Some(val) = ct.strip_prefix("pin=") {
                if val == pin {
                    return true;
                }
            }
        }
    }
    false
}

fn send_response(mut stream: &TcpStream, status: &str, content_type: &str, body: &[u8], cookie: Option<&str>, extra_headers: Option<&[(&str, &str)]>) {
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
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: *\r\n{}{}Connection: close\r\n\r\n",
        status, content_type, body.len(), cookie_header, extra
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(body);
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

fn handle_connection(mut stream: TcpStream, ip: &str, pin: &str, key_hex: &str) {
    let (req, buffer) = match read_full_http_request(&mut stream) {
        Some(res) => res,
        None => return,
    };

    let authorized = is_authorized(&req, pin);

    if req.path == "/api/status" {
        let (wan_active, wan_connecting, wan_url) = get_wan_status();
        let mode = get_active_mode();
        let active_url = if mode == "WAN" {
            if let Some(ref u) = wan_url {
                format!("{}/?pin={}#key={}", u, pin, key_hex)
            } else {
                format!("http://{}:{}/?pin={}#key={}", ip, PORT, pin, key_hex)
            }
        } else {
            format!("http://{}:{}/?pin={}#key={}", ip, PORT, pin, key_hex)
        };
        let resp = serde_json::json!({
            "status": "ACTIVE",
            "port": PORT,
            "ip": ip,
            "tailscale_ip": get_tailscale_ip(),
            "pin": pin,
            "mode": mode,
            "wan_active": wan_active,
            "wan_connecting": wan_connecting,
            "wan_provider": if wan_active || wan_connecting { get_wan_provider() } else { None },
            "wan_url": wan_url,
            "active_url": active_url,
            "auth_required": true
        });
        send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    // --- P2P AIRDROP ENDPOINTS ---
    if req.path == "/api/p2p/ping" {
        let (id, _) = get_or_create_device_id();
        let (vis, _) = get_visibility();
        let resp = serde_json::json!({
            "status": "OK",
            "id": id,
            "name": get_system_hostname(),
            "mode": vis
        });
        send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    if req.method == "GET" && req.path == "/api/p2p/peers" {
        let peers = get_discovered_peers();
        let (vis, remaining) = get_visibility();
        let resp = serde_json::json!({
            "peers": peers,
            "visibility": vis,
            "remaining_secs": remaining,
            "bluetooth_available": is_bluetooth_available()
        });
        send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    if req.method == "POST" && req.path == "/api/p2p/request" {
        let (vis, _) = get_visibility();
        if vis == "OFF" {
            let err = serde_json::json!({ "error": "Recipient AirBridge visibility is turned Off" });
            send_response(&stream, "403 Forbidden", "application/json", err.to_string().as_bytes(), None, None);
            return;
        }

        let body_slice = &buffer[req.body_offset..];
        let req_data: serde_json::Value = match serde_json::from_slice(body_slice) {
            Ok(v) => v,
            Err(_) => {
                send_response(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid JSON request\"}", None, None);
                return;
            }
        };

        let sender_id = req_data["sender_id"].as_str().unwrap_or("unknown").to_string();
        let sender_name = req_data["sender_name"].as_str().unwrap_or("Unknown Omarchy Device").to_string();
        let sender_ip = req_data["sender_ip"].as_str().unwrap_or("").to_string();
        let is_trusted = is_peer_trusted(&sender_id);

        if vis == "KNOWN" && !is_trusted {
            let err = serde_json::json!({ "error": "Peer is not in trusted peers list and visibility is set to Known Only" });
            send_response(&stream, "403 Forbidden", "application/json", err.to_string().as_bytes(), None, None);
            return;
        }

        let mut file_names = Vec::new();
        let mut total_size_bytes = 0u64;
        if let Some(arr) = req_data["files"].as_array() {
            for item in arr {
                if let Some(n) = item["name"].as_str() {
                    file_names.push(sanitize_filename(n));
                }
                if let Some(sz) = item["size_bytes"].as_u64() {
                    total_size_bytes = total_size_bytes.saturating_add(sz);
                }
            }
        }

        let mut token_bytes = [0u8; 16];
        let _ = getrandom::getrandom(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        let transfer = PendingFileTransfer {
            token: token.clone(),
            sender_id,
            sender_name: sender_name.clone(),
            sender_ip,
            file_names: file_names.clone(),
            total_size_bytes,
            created_at: now,
            expires_at: now.saturating_add(30),
            status: "PENDING".to_string(),
        };
        save_pending_transfer(&transfer);

        let size_mb = (total_size_bytes as f64) / 1024.0 / 1024.0;
        notify_desktop(
            "OmaSend AirBridge: Transfer Request",
            &format!("'{}' wants to send {} file(s) ({:.1} MB).\nOpen OmaSend panel to Accept or Decline.", sender_name, file_names.len(), size_mb),
        );

        let resp = serde_json::json!({
            "status": "PENDING",
            "token": token
        });
        send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        return;
    }

    if req.path.starts_with("/api/p2p/decision") {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if req.method == "GET" {
            let token = req.get_param("token").unwrap_or_default();
            if let Some(pending) = get_pending_transfer() {
                if pending.token == token {
                    if now > pending.expires_at {
                        send_response(&stream, "200 OK", "application/json", b"{\"status\":\"EXPIRED\"}", None, None);
                    } else {
                        let resp = serde_json::json!({ "status": pending.status });
                        send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
                    }
                    return;
                }
            }
            send_response(&stream, "404 Not Found", "application/json", b"{\"status\":\"NOT_FOUND\"}", None, None);
            return;
        } else if req.method == "POST" {
            let body_slice = &buffer[req.body_offset..];
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_slice) {
                let token = val["token"].as_str().unwrap_or_default();
                let action = val["action"].as_str().unwrap_or_default();
                if let Some(mut pending) = get_pending_transfer() {
                    if pending.token == token {
                        if action == "accept" {
                            pending.status = "ACCEPTED".to_string();
                            save_pending_transfer(&pending);
                            add_trusted_peer(&pending.sender_id, &pending.sender_name, "");
                            notify_desktop("OmaSend AirBridge", "Transfer accepted. Receiving files...");
                            send_response(&stream, "200 OK", "application/json", b"{\"status\":\"ACCEPTED\"}", None, None);
                            return;
                        } else if action == "reject" {
                            pending.status = "REJECTED".to_string();
                            save_pending_transfer(&pending);
                            notify_desktop("OmaSend AirBridge", "Transfer declined.");
                            send_response(&stream, "200 OK", "application/json", b"{\"status\":\"REJECTED\"}", None, None);
                            return;
                        }
                    }
                }
            }
            send_response(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid token or action\"}", None, None);
            return;
        }
    }

    if req.method == "POST" && req.path.starts_with("/api/p2p/upload") {
        let token = req.get_param("token").unwrap_or_default();
        let filename_raw = req.get_param("filename").unwrap_or_default();
        let clean_filename = sanitize_filename(&urlencoding_decode(&filename_raw));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        if let Some(pending) = get_pending_transfer() {
            if pending.token == token && pending.status == "ACCEPTED" && now <= pending.expires_at {
                let body = &buffer[req.body_offset..];
                let ddir = get_download_dir();
                let file_path = get_unique_filepath(&ddir, &clean_filename);
                if write_secure_bytes(&file_path, body).is_ok() {
                    RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
                    clear_pending_transfer();
                    let final_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    notify_desktop(
                        "OmaSend: AirBridge Transfer Complete",
                        &format!("'{}' ({} bytes) received and saved to Downloads/omasend.", final_name, body.len())
                    );
                    let resp = serde_json::json!({
                        "status": "OK",
                        "filename": final_name,
                        "size": body.len()
                    });
                    send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
                    return;
                } else {
                    send_response(&stream, "500 Internal Server Error", "text/plain", b"Failed to write file to disk", None, None);
                    return;
                }
            }
        }
        send_response(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Unauthorized or expired transfer token\"}", None, None);
        return;
    }

    if req.method == "POST" && req.path == "/api/p2p/clipboard" {
        let (vis, _) = get_visibility();
        if vis == "OFF" {
            send_response(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Visibility is Off\"}", None, None);
            return;
        }
        let body_slice = &buffer[req.body_offset..];
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_slice) {
            let sender_id = val["sender_id"].as_str().unwrap_or_default();
            let sender_name = val["sender_name"].as_str().unwrap_or("Nearby Device");
            let is_trusted = is_peer_trusted(sender_id);
            if vis == "KNOWN" && !is_trusted {
                send_response(&stream, "403 Forbidden", "application/json", b"{\"error\":\"Peer not trusted\"}", None, None);
                return;
            }
            if let Some(text) = val["text"].as_str() {
                if text.len() <= 1_048_576 {
                    set_pc_clipboard(text);
                    notify_desktop("OmaSend: Universal Clipboard", &format!("Received clipboard text from {}.", sender_name));
                    send_response(&stream, "200 OK", "application/json", b"{\"status\":\"OK\"}", None, None);
                    return;
                }
            }
        }
        send_response(&stream, "400 Bad Request", "application/json", b"{\"error\":\"Invalid clipboard payload\"}", None, None);
        return;
    }

    if !authorized {
        let html = render_login_page();
        send_response(&stream, "200 OK", "text/html; charset=utf-8", html.as_bytes(), None, None);
        return;
    }

    let set_cookie = Some(format!("pin={}", pin));

    if req.method == "GET" && req.path == "/" {
        let shared_files = get_directory_files(&get_shared_dir());
        let html = render_web_app(ip, &shared_files);
        send_response(&stream, "200 OK", "text/html; charset=utf-8", html.as_bytes(), set_cookie.as_deref(), None);
    }
    else if req.method == "POST" && req.path == "/api/upload-encrypted" {
        let filename_raw = req.get_header("x-omasend-filename").unwrap_or("received_file.bin");
        let filename_decoded = urlencoding_decode(filename_raw);
        let clean_filename = sanitize_filename(&filename_decoded);

        let iv_hex = match req.get_header("x-omasend-iv") {
            Some(iv) if iv.len() == 24 => iv,
            _ => {
                send_response(&stream, "400 Bad Request", "text/plain", b"Missing or invalid X-OmaSend-IV", None, None);
                return;
            }
        };

        let iv_bytes = match hex::decode(iv_hex) {
            Ok(b) => b,
            Err(_) => {
                send_response(&stream, "400 Bad Request", "text/plain", b"Invalid IV hex", None, None);
                return;
            }
        };

        let body = &buffer[req.body_offset..];
        match decrypt_aes256_gcm(key_hex, &iv_bytes, body) {
            Ok(decrypted) => {
                let ddir = get_download_dir();
                let file_path = get_unique_filepath(&ddir, &clean_filename);
                if write_secure_bytes(&file_path, &decrypted).is_ok() {
                    RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
                    notify_desktop(
                        "OmaSend: E2EE File Received",
                        &format!("'{}' ({} bytes) decrypted and saved to Downloads/omasend.", file_path.file_name().unwrap().to_string_lossy(), decrypted.len())
                    );
                    let resp = serde_json::json!({
                        "status": "OK",
                        "filename": clean_filename,
                        "size": decrypted.len(),
                        "encrypted": true
                    });
                    send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
                } else {
                    send_response(&stream, "500 Internal Server Error", "text/plain", b"Failed to write file", None, None);
                }
            }
            Err(e) => {
                eprintln!("Decryption error: {}", e);
                send_response(&stream, "400 Bad Request", "text/plain", e.as_bytes(), None, None);
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

        if let Ok(content) = safe_read_file(&actual_target) {
            match encrypt_aes256_gcm(key_hex, &content) {
                Ok((iv, ciphertext)) => {
                    let iv_hex = hex::encode(iv);
                    let cd_val = format!("attachment; filename=\"{}.enc\"", filename);
                    let extra = [
                        ("X-OmaSend-IV", iv_hex.as_str()),
                        ("X-OmaSend-Filename", filename.as_str()),
                        ("Content-Disposition", cd_val.as_str()),
                    ];
                    send_response(&stream, "200 OK", "application/octet-stream", &ciphertext, None, Some(&extra));
                    return;
                }
                Err(e) => {
                    send_response(&stream, "500 Internal Server Error", "text/plain", e.as_bytes(), None, None);
                    return;
                }
            }
        }
        send_response(&stream, "404 Not Found", "text/plain", b"File not found or access denied", None, None);
    }
    else if req.method == "POST" && req.path == "/api/clipboard-encrypted" {
        let iv_hex = match req.get_header("x-omasend-iv") {
            Some(iv) if iv.len() == 24 => iv,
            _ => {
                send_response(&stream, "400 Bad Request", "text/plain", b"Missing IV", None, None);
                return;
            }
        };
        let iv_bytes = match hex::decode(iv_hex) {
            Ok(b) => b,
            Err(_) => {
                send_response(&stream, "400 Bad Request", "text/plain", b"Invalid IV hex", None, None);
                return;
            }
        };

        let body = &buffer[req.body_offset..];
        match decrypt_aes256_gcm(key_hex, &iv_bytes, body) {
            Ok(decrypted) => {
                let text = String::from_utf8_lossy(&decrypted).to_string();
                set_pc_clipboard(&text);
                notify_desktop(
                    "OmaSend: E2EE Clipboard Received",
                    &format!("Encrypted clipboard updated ({} chars):\n{}", text.len(), text.chars().take(60).collect::<String>()),
                );
                let resp = serde_json::json!({ "status": "OK", "encrypted": true });
                send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
            }
            Err(e) => {
                send_response(&stream, "400 Bad Request", "text/plain", e.as_bytes(), None, None);
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
                send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
            }
            Err(e) => {
                send_response(&stream, "500 Internal Server Error", "text/plain", e.as_bytes(), None, None);
            }
        }
    }
    else if req.path == "/api/clipboard" {
        if req.method == "GET" {
            let clip = get_pc_clipboard();
            let resp = serde_json::json!({ "clipboard": clip });
            send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        } else if req.method == "POST" {
            let body = String::from_utf8_lossy(&buffer[req.body_offset..]);
            let text = if let Some(val) = body.strip_prefix("text=") {
                urlencoding_decode(val)
            } else {
                body.to_string()
            };
            set_pc_clipboard(&text);
            notify_desktop("OmaSend: Clipboard Received", &format!("Clipboard updated from device ({} chars)", text.len()));
            let resp = serde_json::json!({ "status": "OK" });
            send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None, None);
        }
    }
    else if req.method == "GET" && req.path.starts_with("/download/") {
        let filename = sanitize_filename(&urlencoding_decode(req.path.trim_start_matches("/download/")));
        let target = get_shared_dir().join(&filename);
        let actual_target = if target.exists() { target } else { get_download_dir().join(&filename) };
        if let Ok(content) = safe_read_file(&actual_target) {
            let cd_val = format!("attachment; filename=\"{}\"", filename);
            let extra = [("Content-Disposition", cd_val.as_str())];
            send_response(&stream, "200 OK", "application/octet-stream", &content, None, Some(&extra));
            return;
        }
        send_response(&stream, "404 Not Found", "text/plain", b"File not found or access denied", None, None);
    }
    else if req.method == "POST" && req.path == "/upload" {
        let ddir = get_download_dir();
        let body = &buffer[req.body_offset..];
        let mut saved_name = format!("transfer_{}.bin", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        let body_str = String::from_utf8_lossy(body);
        if let Some(pos) = body_str.find("filename=\"") {
            if let Some(end) = body_str[pos + 10..].find('"') {
                saved_name = sanitize_filename(&body_str[pos + 10..pos + 10 + end]);
            }
        }
        let file_path = get_unique_filepath(&ddir, &saved_name);
        let data_start = body.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(0);
        let data_slice = if data_start < body.len() { &body[data_start..] } else { body };

        let _ = write_secure_bytes(&file_path, data_slice);
        RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
        notify_desktop(
            "OmaSend: File Received",
            &format!("'{}' saved to Downloads/omasend.", file_path.file_name().unwrap().to_string_lossy()),
        );
        let resp = "{\"status\":\"OK\"}";
        send_response(&stream, "200 OK", "application/json", resp.as_bytes(), None, None);
    } else {
        send_response(&stream, "404 Not Found", "text/plain", b"Not Found", None, None);
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

    for s in listener.incoming().flatten() {
        let ip_clone = local_ip.clone();
        let pin_clone = pin.clone();
        let key_clone = key.clone();
        thread::spawn(move || {
            handle_connection(s, &ip_clone, &pin_clone, &key_clone);
        });
    }
}

// ------------------- CLI ENTRYPOINT -------------------

fn main() {
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

    if let Some(pos) = args.iter().position(|a| a == "--set-visibility") {
        if let Some(mode) = args.get(pos + 1) {
            set_visibility(mode);
            println!("AirBridge visibility set to {}", mode.to_uppercase());
            return;
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--accept-transfer") {
        if let Some(token) = args.get(pos + 1) {
            if let Some(mut pending) = get_pending_transfer() {
                if pending.token == *token {
                    pending.status = "ACCEPTED".to_string();
                    save_pending_transfer(&pending);
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

    if let Some(pos) = args.iter().position(|a| a == "--send-p2p") {
        if let (Some(target_ip), Some(file_path_str)) = (args.get(pos + 1), args.get(pos + 2)) {
            let path = Path::new(file_path_str);
            match p2p_send_file_to_peer(target_ip, path) {
                Ok(()) => println!("File sent successfully to {}", target_ip),
                Err(e) => eprintln!("Error sending file: {}", e),
            }
            return;
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--send-dialog") {
        if let Some(target_ip) = args.get(pos + 1) {
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
                    match p2p_send_file_to_peer(target_ip, path) {
                        Ok(()) => println!("File successfully sent to {}", target_ip),
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
            total_received: RECEIVED_COUNTER.load(Ordering::SeqCst),
            recent_files: get_directory_files(&get_download_dir()),
            shared_files: get_directory_files(&get_shared_dir()),
            p2p_device_id: dev_id,
            p2p_hostname: get_system_hostname(),
            p2p_visibility: vis,
            p2p_visibility_remaining_secs: rem,
            p2p_bluetooth_available: is_bluetooth_available(),
            p2p_discovered_peers: get_discovered_peers(),
            p2p_pending_transfer: get_pending_transfer(),
        };
        println!("{}", serde_json::to_string_pretty(&state).unwrap());
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
            name: "Omarchy-PC".to_string(),
            ip: "192.168.1.81".to_string(),
            port: 8844,
            mode: "KNOWN".to_string(),
            bt: true,
            fp: "deadbeef".to_string(),
        };
        let serialized = serde_json::to_string(&packet).expect("Must serialize");
        let deserialized: P2pBeaconPacket = serde_json::from_str(&serialized).expect("Must deserialize");
        assert_eq!(deserialized.magic, "OMASEND_P2P");
        assert_eq!(deserialized.id, "abc123");
        assert!(deserialized.bt);
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
}
