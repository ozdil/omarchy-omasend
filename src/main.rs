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
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

extern "C" {
    fn getuid() -> u32;
}

const PORT: u16 = 8844;
static RECEIVED_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size_str: String,
    pub size_bytes: u64,
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
    if let Ok(out) = Command::new("tailscale").args(["ip", "-4"]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

fn get_current_uid() -> u32 {
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

/// Atomically writes a sensitive file with mode 0600:
/// - Verifies that existing target is not an untrusted symlink or foreign file
/// - Creates a temporary file in the same directory with mode 0600
/// - Writes data and syncs
/// - Atomically replaces destination file via rename
/// - Re-asserts mode 0600 on destination
fn write_secure_file(path: &Path, content: &str) -> Result<(), String> {
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

        file.write_all(content.as_bytes())
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
    let _ = fs::write(&mode_file, mode);
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
    fs::read_to_string(&provider_file).ok().map(|s| s.trim().to_string())
}

fn is_cloudflare_rate_limited() -> bool {
    let log_file = get_state_dir().join("wan_tunnel.log");
    if let Ok(meta) = fs::metadata(&log_file) {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() < 900 {
                    if let Ok(content) = fs::read_to_string(&log_file) {
                        if content.contains("429 Too Many Requests") || content.contains("error code: 1015") {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn get_localtunnel_bin() -> Option<(String, Vec<String>)> {
    // Look for fixed immutable localtunnel binary pre-installed in PATH or ~/.local/bin.
    // Never executes mutable runtime npm packages via npx.
    if let Ok(out) = Command::new("which").arg("localtunnel").output() {
        if out.status.success() {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !path.is_empty() && Path::new(&path).is_file() {
                return Some((path, vec!["--port".to_string(), PORT.to_string()]));
            }
        }
    }
    let home = env::var("HOME").unwrap_or_default();
    let local_bin = format!("{}/.local/bin/localtunnel", home);
    if Path::new(&local_bin).is_file() {
        return Some((local_bin, vec!["--port".to_string(), PORT.to_string()]));
    }
    None
}

fn launch_localtunnel() -> Result<u32, String> {
    let (bin, args) = get_localtunnel_bin().ok_or_else(|| "No localtunnel binary found".to_string())?;
    let lt_log = get_state_dir().join("localtunnel.log");
    let _ = fs::remove_file(&lt_log);
    let _ = fs::remove_file(get_state_dir().join("wan_tunnel.log"));
    let out_file = fs::File::create(&lt_log).map_err(|e| e.to_string())?;
    let err_file = out_file.try_clone().map_err(|e| e.to_string())?;

    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(out_file)
        .stderr(err_file)
        .process_group(0);

    let child = cmd.spawn().map_err(|e| format!("Failed to spawn localtunnel: {}", e))?;
    let pid = child.id();
    let pid_file = get_state_dir().join("wan_pid.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let provider_file = get_state_dir().join("wan_provider.txt");
    let _ = fs::write(&pid_file, pid.to_string());
    let _ = fs::write(&connecting_file, "connecting");
    let _ = fs::write(&provider_file, "Localtunnel");
    set_active_mode("WAN");
    Ok(pid)
}

fn get_wan_status() -> (bool, bool, Option<String>) {
    let pid_file = get_state_dir().join("wan_pid.txt");
    let url_file = get_state_dir().join("wan_url.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let log_file = get_state_dir().join("wan_tunnel.log");
    let lt_log = get_state_dir().join("localtunnel.log");
    let fallback_file = get_state_dir().join("fallback_attempted.txt");

    if let Ok(pid_str) = fs::read_to_string(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if is_process_alive(pid) {
                // If URL is already recorded, return immediately
                if let Ok(url) = fs::read_to_string(&url_file) {
                    let u = url.trim().to_string();
                    if !u.is_empty() {
                        let _ = fs::remove_file(&connecting_file);
                        return (true, false, Some(u));
                    }
                }

                let provider = get_wan_provider().unwrap_or_else(|| "Cloudflare".to_string());

                if provider == "Localtunnel" {
                    // Check localtunnel log
                    if let Ok(content) = fs::read_to_string(&lt_log) {
                        for line in content.lines() {
                            if let Some(pos) = line.find("https://") {
                                let rest = &line[pos..];
                                let end = rest.find(|c: char| c.is_whitespace() || c == '\r' || c == '\n').unwrap_or(rest.len());
                                let u = rest[..end].trim().to_string();
                                if !u.is_empty() && u.contains(".loca.lt") {
                                    let _ = fs::write(&url_file, &u);
                                    let _ = fs::remove_file(&connecting_file);
                                    let _ = fs::remove_file(&fallback_file);
                                    set_active_mode("WAN");
                                    update_all_qr();
                                    notify_desktop(
                                        "OmaSend: Global WAN Active",
                                        &format!("Global AirBridge ready!\nAddress: {}", u),
                                    );
                                    return (true, false, Some(u));
                                }
                            }
                        }
                    }
                    return (false, true, None);
                } else {
                    // Check Cloudflare log for resolved trycloudflare URL or rate limit
                    if let Ok(content) = fs::read_to_string(&log_file) {
                        if content.contains("429 Too Many Requests") || content.contains("error code: 1015") {
                            let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
                            let _ = fs::remove_file(&log_file);
                            if !fallback_file.exists() {
                                let _ = fs::write(&fallback_file, "1");
                                let _ = launch_localtunnel();
                                return (false, true, None);
                            }
                        }

                        for line in content.lines() {
                            if let Some(pos) = line.find("https://") {
                                let rest = &line[pos..];
                                if let Some(end) = rest.find(".trycloudflare.com") {
                                    let found_url = rest[..end + 18].to_string();
                                    let _ = fs::write(&url_file, &found_url);
                                    let _ = fs::remove_file(&connecting_file);
                                    let _ = fs::remove_file(&fallback_file);
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
            } else {
                // Process died while we were connecting: attempt localtunnel fallback if was Cloudflare!
                if connecting_file.exists() && !fallback_file.exists() {
                    let _ = fs::write(&fallback_file, "1");
                    if launch_localtunnel().is_ok() {
                        return (false, true, None);
                    }
                }
            }
        }
    }
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&url_file);
    let _ = fs::remove_file(&connecting_file);
    let _ = fs::remove_file(&fallback_file);
    (false, false, None)
}

fn stop_wan_tunnel() {
    let pid_file = get_state_dir().join("wan_pid.txt");
    let url_file = get_state_dir().join("wan_url.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let provider_file = get_state_dir().join("wan_provider.txt");
    let fallback_file = get_state_dir().join("fallback_attempted.txt");

    if let Ok(pid_str) = fs::read_to_string(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
        }
    }
    let _ = Command::new("pkill").args(["-9", "-f", "cloudflared tunnel"]).output();
    let _ = Command::new("pkill").args(["-9", "-f", "localtunnel"]).output();
    let _ = Command::new("pkill").args(["-9", "-f", "lt --port"]).output();

    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&url_file);
    let _ = fs::remove_file(&connecting_file);
    let _ = fs::remove_file(&provider_file);
    let _ = fs::remove_file(&fallback_file);
    set_active_mode("LAN");
    update_all_qr();
    notify_desktop("OmaSend: Global WAN", "Secure WAN tunnel closed. Switched to local Wi-Fi mode.");
}

fn start_wan_tunnel() -> Result<String, String> {
    let (active, connecting, url) = get_wan_status();
    if active && url.is_some() {
        set_active_mode("WAN");
        update_all_qr();
        return Ok(url.unwrap());
    }
    if connecting {
        return Ok("Tunnel already initializing...".to_string());
    }

    // Clean up any stale instances before starting
    let _ = Command::new("pkill").args(["-9", "-f", "cloudflared tunnel"]).output();
    let _ = Command::new("pkill").args(["-9", "-f", "localtunnel"]).output();
    let _ = Command::new("pkill").args(["-9", "-f", "lt --port"]).output();

    let pid_file = get_state_dir().join("wan_pid.txt");
    let url_file = get_state_dir().join("wan_url.txt");
    let connecting_file = get_state_dir().join("wan_connecting.txt");
    let provider_file = get_state_dir().join("wan_provider.txt");
    let fallback_file = get_state_dir().join("fallback_attempted.txt");
    let _ = fs::remove_file(&url_file);
    let _ = fs::remove_file(&fallback_file);

    // If Cloudflare is currently rate-limited on TryCloudflare, go directly to Localtunnel
    if is_cloudflare_rate_limited() {
        if let Ok(_) = launch_localtunnel() {
            return Ok("Localtunnel launched (Cloudflare rate-limited)".to_string());
        }
    }

    let cloudflared_bin = if let Ok(out) = Command::new("which").arg("cloudflared").output() {
        if out.status.success() {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !path.is_empty() && Path::new(&path).is_file() {
                Some(path)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        let home = env::var("HOME").unwrap_or_default();
        let local_bin = format!("{}/.local/bin/cloudflared", home);
        if Path::new(&local_bin).is_file() {
            Some(local_bin)
        } else {
            None
        }
    };

    if let Some(bin) = cloudflared_bin {
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
                let _ = fs::write(&pid_file, pid.to_string());
                let _ = fs::write(&connecting_file, "connecting");
                let _ = fs::write(&provider_file, "Cloudflare");
                set_active_mode("WAN");
                return Ok("Cloudflare tunnel launched in background".to_string());
            }
            Err(e) => {
                eprintln!("Failed to spawn cloudflared: {}, trying localtunnel fallback...", e);
            }
        }
    }

    // Fallback: localtunnel
    if let Ok(_) = launch_localtunnel() {
        return Ok("Localtunnel launched in background".to_string());
    }

    Err("No supported WAN tunnel client installed. Please install cloudflared ('sudo pacman -S cloudflared') or localtunnel ('npm install -g localtunnel@2.0.2'). See README.md.".to_string())
}

// ------------------- QR CODE & URLS -------------------

fn update_all_qr() {
    let ip = get_local_ip();
    let pin = get_or_create_pin();
    let key = get_or_create_session_key();
    let mode = get_active_mode();
    let (_wan_active, _wan_connecting, wan_url) = get_wan_status();

    let target_base = if mode == "WAN" && wan_url.is_some() {
        wan_url.unwrap()
    } else {
        format!("http://{}:{}", ip, PORT)
    };

    let full_url = format!("{}/?pin={}#key={}", target_base, pin, key);

    let last_qr_file = get_state_dir().join("last_qr_url.txt");
    let qr_file = get_state_dir().join("qr.svg");

    if qr_file.exists() {
        if let Ok(last_url) = fs::read_to_string(&last_qr_file) {
            if last_url.trim() == full_url {
                return; // Cached: URL has not changed
            }
        }
    }

    let qr_path = qr_file.to_string_lossy().to_string();
    let _ = Command::new("qrencode")
        .args(["-o", &qr_path, "-t", "SVG", &full_url])
        .output();
    let _ = fs::write(&last_qr_file, &full_url);
}

fn notify_desktop(title: &str, body: &str) {
    let _ = Command::new("notify-send")
        .args(["-a", "OmaSend", "-i", "document-send", title, body])
        .spawn();
}

fn get_pc_clipboard() -> String {
    if let Ok(output) = Command::new("wl-paste").args(["--no-newline"]).output() {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).to_string();
        }
    }
    String::new()
}

fn set_pc_clipboard(text: &str) {
    if let Ok(mut child) = Command::new("wl-copy").stdin(Stdio::piped()).spawn() {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
    }
}

fn sanitize_filename(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_' || *c == ' ')
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed.starts_with('.') {
        format!("file_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
    } else {
        trimmed.to_string()
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
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(meta) = entry.metadata() {
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
    files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    files
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
}

fn read_full_http_request(stream: &mut TcpStream) -> Option<(HttpRequest, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(65536);
    let mut temp = [0u8; 16384];
    let mut header_end = None;
    let mut content_length: usize = 0;

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
                        }
                    }
                }
            }
        }

        if let Some(hend) = header_end {
            if buffer.len() >= hend + content_length {
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
        let active_url = if mode == "WAN" && wan_url.is_some() {
            format!("{}/?pin={}#key={}", wan_url.as_ref().unwrap(), pin, key_hex)
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
                if fs::write(&file_path, &decrypted).is_ok() {
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
        let actual_target = if target.is_file() {
            target
        } else {
            get_download_dir().join(&filename)
        };

        if actual_target.is_file() {
            if let Ok(content) = fs::read(&actual_target) {
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
        }
        send_response(&stream, "404 Not Found", "text/plain", b"File not found", None, None);
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
        let actual_target = if target.is_file() { target } else { get_download_dir().join(&filename) };
        if actual_target.is_file() {
            if let Ok(content) = fs::read(&actual_target) {
                let cd_val = format!("attachment; filename=\"{}\"", filename);
                let extra = [("Content-Disposition", cd_val.as_str())];
                send_response(&stream, "200 OK", "application/octet-stream", &content, None, Some(&extra));
                return;
            }
        }
        send_response(&stream, "404 Not Found", "text/plain", b"File not found", None, None);
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

        let _ = fs::write(&file_path, data_slice);
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

    for stream in listener.incoming() {
        if let Ok(s) = stream {
            let ip_clone = local_ip.clone();
            let pin_clone = pin.clone();
            let key_clone = key.clone();
            thread::spawn(move || {
                handle_connection(s, &ip_clone, &pin_clone, &key_clone);
            });
        }
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

    let active_url = if active_mode == "WAN" && wan_url.is_some() {
        format!("{}/?pin={}#key={}", wan_url.as_ref().unwrap(), pin, session_key)
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
}
