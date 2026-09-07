use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const PORT: u16 = 8844;
static RECEIVED_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size_str: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerState {
    pub status: String,
    pub port: u16,
    pub local_ip: String,
    pub pin: String,
    pub download_dir: String,
    pub shared_dir: String,
    pub qr_path: String,
    pub total_received: usize,
    pub recent_files: Vec<FileInfo>,
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

fn get_state_dir() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = Path::new(&home).join(".local/state/omarchy/omasend");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn get_download_dir() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = Path::new(&home).join("Downloads/omasend");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn get_shared_dir() -> PathBuf {
    let dir = get_download_dir().join("shared");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn get_or_create_pin() -> String {
    let pin_file = get_state_dir().join("pin.txt");
    if let Ok(content) = fs::read_to_string(&pin_file) {
        let p = content.trim();
        if p.len() == 4 && p.chars().all(|c| c.is_ascii_digit()) {
            return p.to_string();
        }
    }
    generate_new_pin()
}

fn generate_new_pin() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(12345);
    let pin = format!("{:04}", (now % 9000) + 1000);
    let pin_file = get_state_dir().join("pin.txt");
    let _ = fs::write(&pin_file, &pin);
    pin
}

fn update_qr_code(ip: &str, pin: &str) -> String {
    let qr_file = get_state_dir().join("qr.svg");
    let qr_path = qr_file.to_string_lossy().to_string();
    let url = format!("http://{}:{}/?pin={}", ip, PORT, pin);
    let _ = Command::new("qrencode")
        .args(["-o", &qr_path, "-t", "SVG", &url])
        .output();
    qr_path
}

fn notify_desktop(title: &str, body: &str) {
    let _ = Command::new("notify-send")
        .args(["-a", "OmaSend", "-i", "network-wireless", title, body])
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
    if let Ok(mut child) = Command::new("wl-copy").stdin(std::process::Stdio::piped()).spawn() {
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

fn get_recent_files() -> Vec<FileInfo> {
    let ddir = get_download_dir();
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(&ddir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(meta) = entry.metadata() {
                    let size_bytes = meta.len();
                    let size_str = if size_bytes > 1_000_000 {
                        format!("{:.1} MB", size_bytes as f64 / 1_000_000.0)
                    } else if size_bytes > 1_000 {
                        format!("{:.1} KB", size_bytes as f64 / 1_000.0)
                    } else {
                        format!("{} B", size_bytes)
                    };
                    files.push(FileInfo {
                        name: entry.file_name().to_string_lossy().to_string(),
                        size_str,
                    });
                }
            }
        }
    }
    files.truncate(8);
    files
}

// Simple HTTP request parsing
struct HttpRequest {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body_offset: usize,
}

fn parse_http_request(raw: &[u8]) -> Option<HttpRequest> {
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_str = String::from_utf8_lossy(&raw[..header_end]);
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

    Some(HttpRequest {
        method,
        path,
        query,
        headers,
        body_offset: header_end + 4,
    })
}

fn is_authorized(req: &HttpRequest, pin: &str) -> bool {
    // Check query param pin
    for part in req.query.split('&') {
        if let Some(val) = part.strip_prefix("pin=") {
            if val == pin {
                return true;
            }
        }
    }
    // Check X-OmaSend-Pin header
    for (k, v) in &req.headers {
        if k == "x-omasend-pin" && v == pin {
            return true;
        }
        if k == "cookie" {
            for c in v.split(';') {
                let ct = c.trim();
                if let Some(val) = ct.strip_prefix("pin=") {
                    if val == pin {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn send_response(mut stream: &TcpStream, status: &str, content_type: &str, body: &[u8], cookie: Option<&str>) {
    let cookie_header = if let Some(c) = cookie {
        format!("Set-Cookie: {}; Path=/; HttpOnly; SameSite=Lax\r\n", c)
    } else {
        String::new()
    };
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
        status, content_type, body.len(), cookie_header
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(body);
}

fn render_login_page(ip: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>OmaSend • PIN Doğrulama</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #070a0e; color: #dbe4ee; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
.card {{ background: #0e141d; border: 1px solid #1a2332; border-radius: 12px; padding: 32px 24px; width: 100%; max-width: 360px; text-align: center; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }}
.icon {{ font-size: 40px; margin-bottom: 12px; }}
h1 {{ font-size: 20px; font-weight: 700; color: #dbe4ee; margin-bottom: 4px; }}
p {{ font-size: 13px; color: #8899a6; margin-bottom: 24px; }}
.pin-input {{ width: 100%; font-size: 28px; letter-spacing: 12px; text-align: center; background: #070a0e; border: 2px solid #00cbb8; color: #00eed9; border-radius: 8px; padding: 12px; margin-bottom: 20px; font-family: monospace; outline: none; }}
button {{ width: 100%; background: #00cbb8; color: #070a0e; border: none; padding: 14px; font-size: 15px; font-weight: bold; border-radius: 8px; cursor: pointer; }}
</style>
</head>
<body>
<div class="card">
<div class="icon">🔒</div>
<h1>OmaSend AirBridge</h1>
<p>Omarchy PC ekranında görünen 4 haneli PIN kodunu girin.</p>
<form method="GET" action="/">
<input type="number" name="pin" class="pin-input" placeholder="••••" required autofocus pattern="[0-9]*" inputmode="numeric">
<button type="submit">Bağlan ve Doğrula</button>
</form>
</div>
</body>
</html>"#
    )
}

fn render_web_app(ip: &str, pin: &str, clipboard_preview: &str, shared_files: &[FileInfo]) -> String {
    let mut files_html = String::new();
    if shared_files.is_empty() {
        files_html.push_str("<div class='empty'>PC'den paylaşılan dosya yok</div>");
    } else {
        for f in shared_files {
            files_html.push_str(&format!(
                r#"<div class="file-item">
<div class="file-info"><div class="file-name">{}</div><div class="file-size">{}</div></div>
<a href="/download/{}" class="btn-sm">İndir 📥</a>
</div>"#,
                f.name, f.size_str, f.name
            ));
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>OmaSend AirBridge</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #070a0e; color: #dbe4ee; padding: 16px; max-width: 540px; margin: 0 auto; }}
.header {{ display: flex; align-items: center; justify-content: space-between; padding-bottom: 14px; border-bottom: 1px solid #1a2332; margin-bottom: 16px; }}
.brand {{ font-size: 18px; font-weight: bold; color: #00cbb8; display: flex; align-items: center; gap: 8px; }}
.badge {{ font-size: 11px; background: rgba(0, 203, 184, 0.15); border: 1px solid #00cbb8; color: #00cbb8; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
.card {{ background: #0e141d; border: 1px solid #1a2332; border-radius: 10px; padding: 18px; margin-bottom: 16px; }}
.card-title {{ font-size: 12px; font-weight: bold; letter-spacing: 1px; color: #8899a6; text-transform: uppercase; margin-bottom: 12px; }}
.drop-zone {{ border: 2px dashed #00cbb8; border-radius: 8px; padding: 32px 16px; text-align: center; cursor: pointer; background: rgba(0, 203, 184, 0.03); transition: all 0.2s; }}
.drop-zone:hover {{ background: rgba(0, 203, 184, 0.08); }}
.drop-icon {{ font-size: 32px; margin-bottom: 8px; }}
.file-item {{ display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; background: #131b26; border-radius: 6px; margin-bottom: 8px; }}
.file-name {{ font-size: 14px; font-weight: 500; word-break: break-all; }}
.file-size {{ font-size: 12px; color: #8899a6; margin-top: 2px; }}
.btn-sm {{ background: #00cbb8; color: #070a0e; text-decoration: none; padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
textarea {{ width: 100%; height: 80px; background: #070a0e; border: 1px solid #1a2332; border-radius: 6px; color: #dbe4ee; padding: 10px; font-size: 13px; margin-bottom: 10px; resize: vertical; }}
button {{ width: 100%; background: #00cbb8; color: #070a0e; border: none; padding: 12px; font-size: 14px; font-weight: bold; border-radius: 6px; cursor: pointer; }}
.clipboard-box {{ background: #070a0e; border: 1px solid #1a2332; padding: 12px; border-radius: 6px; font-size: 13px; max-height: 100px; overflow-y: auto; margin-bottom: 10px; color: #00eed9; }}
.empty {{ font-size: 13px; color: #8899a6; text-align: center; padding: 12px; }}
#progress-bar {{ display: none; width: 100%; height: 6px; background: #1a2332; border-radius: 3px; overflow: hidden; margin-top: 12px; }}
#progress-fill {{ width: 0%; height: 100%; background: #00cbb8; transition: width 0.2s; }}
</style>
</head>
<body>
<div class="header">
<div class="brand">🚀 OmaSend AirBridge</div>
<div class="badge">BAĞLI: {}</div>
</div>

<div class="card">
<div class="card-title">📤 PC'ye Dosya Gönder</div>
<form id="upload-form" method="POST" action="/upload" enctype="multipart/form-data">
<div class="drop-zone" onclick="document.getElementById('file-input').click()">
<div class="drop-icon">📁</div>
<div style="font-size: 14px; font-weight: bold;">Fotoğraf, Video veya Dosya Seç</div>
<div style="font-size: 12px; color: #8899a6; margin-top: 4px;">veya buraya dokunun</div>
<input type="file" id="file-input" name="file" style="display: none;" onchange="uploadFiles(this.files)" multiple>
</div>
<div id="progress-bar"><div id="progress-fill"></div></div>
<div id="status-msg" style="font-size: 12px; color: #00cbb8; margin-top: 8px; text-align: center;"></div>
</form>
</div>

<div class="card">
<div class="card-title">📋 PC Panosu (Clipboard)</div>
<div class="clipboard-box" id="pc-clip">{}</div>
<button onclick="copyPcClipboard()">Telefona Kopyala</button>
</div>

<div class="card">
<div class="card-title">✏️ PC Panosuna Metin Gönder</div>
<form method="POST" action="/clipboard">
<textarea name="text" placeholder="PC'ye anında yapıştırmak istediğiniz metni yazın..."></textarea>
<button type="submit">PC Panosuna Gönder</button>
</form>
</div>

<div class="card">
<div class="card-title">📥 PC'den İndirilebilecek Dosyalar</div>
{}
</div>

<script>
function copyPcClipboard() {{
  var text = document.getElementById('pc-clip').innerText;
  navigator.clipboard.writeText(text).then(function() {{
    alert('Pano telefona kopyalandı! 📋');
  }});
}}

function uploadFiles(files) {{
  if (!files || files.length === 0) return;
  var formData = new FormData();
  for (var i = 0; i < files.length; i++) {{
    formData.append('file', files[i]);
  }}
  var pBar = document.getElementById('progress-bar');
  var pFill = document.getElementById('progress-fill');
  var sMsg = document.getElementById('status-msg');
  pBar.style.display = 'block';
  sMsg.innerText = 'Gönderiliyor...';

  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/upload', true);
  xhr.upload.onprogress = function(e) {{
    if (e.lengthComputable) {{
      var percent = Math.round((e.loaded / e.total) * 100);
      pFill.style.width = percent + '%';
      sMsg.innerText = 'Yükleniyor: %' + percent;
    }}
  }};
  xhr.onload = function() {{
    pFill.style.width = '100%';
    sMsg.innerText = '✅ Dosya başarıyla PC ye gönderildi!';
    setTimeout(function() {{ location.reload(); }}, 1500);
  }};
  xhr.onerror = function() {{
    sMsg.innerText = '❌ Hata oluştu!';
  }};
  xhr.send(formData);
}}
</script>
</body>
</html>"#,
        ip,
        if clipboard_preview.is_empty() { "(Pano boş)" } else { clipboard_preview },
        files_html
    )
}

fn handle_connection(mut stream: TcpStream, ip: &str, pin: &str) {
    let mut buffer = vec![0u8; 65536];
    let n = match stream.read(&mut buffer) {
        Ok(bytes) if bytes > 0 => bytes,
        _ => return,
    };
    buffer.truncate(n);

    let req = match parse_http_request(&buffer) {
        Some(r) => r,
        None => return,
    };

    let authorized = is_authorized(&req, pin);

    // If request contains ?pin=XYZ and is authorized, set cookie
    let set_cookie = if authorized {
        Some(format!("pin={}", pin))
    } else {
        None
    };

    // Public API status
    if req.path == "/api/status" {
        let resp = serde_json::json!({
            "status": "ACTIVE",
            "port": PORT,
            "ip": ip,
            "auth_required": true
        });
        send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None);
        return;
    }

    if !authorized {
        let html = render_login_page(ip);
        send_response(&stream, "200 OK", "text/html; charset=utf-8", html.as_bytes(), None);
        return;
    }

    // Authenticated routes
    if req.method == "GET" && req.path == "/" {
        let clip = get_pc_clipboard();
        let clip_preview = clip.chars().take(200).collect::<String>();
        let shared_files = get_recent_files();
        let html = render_web_app(ip, pin, &clip_preview, &shared_files);
        send_response(&stream, "200 OK", "text/html; charset=utf-8", html.as_bytes(), set_cookie.as_deref());
    } else if req.path == "/api/clipboard" {
        if req.method == "GET" {
            let clip = get_pc_clipboard();
            let resp = serde_json::json!({ "clipboard": clip });
            send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None);
        } else if req.method == "POST" {
            let body = String::from_utf8_lossy(&buffer[req.body_offset..]);
            let text = if let Some(val) = body.strip_prefix("text=") {
                val.replace('+', " ")
            } else {
                body.to_string()
            };
            set_pc_clipboard(&text);
            notify_desktop("OmaSend: Pano Alındı", &format!("Telefondan pano metni güncellendi ({} karakter)", text.len()));
            let resp = serde_json::json!({ "status": "OK" });
            send_response(&stream, "200 OK", "application/json", resp.to_string().as_bytes(), None);
        }
    } else if req.method == "POST" && (req.path == "/clipboard" || req.path == "/api/clipboard-web") {
        let body = String::from_utf8_lossy(&buffer[req.body_offset..]);
        let clean_text = if let Some(pos) = body.find("text=") {
            let t = &body[pos + 5..];
            t.replace('+', " ")
        } else {
            body.to_string()
        };
        set_pc_clipboard(&clean_text);
        notify_desktop("OmaSend: Pano Alındı", &format!("Telefondan yeni metin panoya kopyalandı:\n{}", clean_text.chars().take(60).collect::<String>()));
        let redirect = "HTTP/1.1 303 See Other\r\nLocation: /\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(redirect.as_bytes());
    } else if req.method == "POST" && (req.path == "/upload" || req.path == "/api/upload") {
        // Parse multipart/form-data or binary body
        let ddir = get_download_dir();
        let body = &buffer[req.body_offset..];
        let mut saved_name = format!("transfer_{}.bin", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

        // Extract filename from header
        let body_str = String::from_utf8_lossy(body);
        if let Some(pos) = body_str.find("filename=\"") {
            if let Some(end) = body_str[pos + 10..].find('"') {
                let raw_name = &body_str[pos + 10..pos + 10 + end];
                saved_name = sanitize_filename(raw_name);
            }
        }

        // Find boundary end if multipart
        let file_path = get_unique_filepath(&ddir, &saved_name);
        // Find actual data payload
        let data_start = body.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(0);
        let data_slice = if data_start < body.len() { &body[data_start..] } else { body };

        let _ = fs::write(&file_path, data_slice);
        RECEIVED_COUNTER.fetch_add(1, Ordering::SeqCst);
        notify_desktop(
            "OmaSend: Dosya Alındı 📥",
            &format!("'{}' başarıyla Downloads/omasend klasörüne kaydedildi.", file_path.file_name().unwrap().to_string_lossy())
        );

        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"status\":\"OK\"}";
        let _ = stream.write_all(resp.as_bytes());
    } else if req.method == "GET" && req.path.starts_with("/download/") {
        let filename = req.path.trim_start_matches("/download/");
        let clean_name = sanitize_filename(filename);
        let target = get_download_dir().join(&clean_name);
        if target.is_file() {
            if let Ok(content) = fs::read(&target) {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    clean_name, content.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&content);
                return;
            }
        }
        send_response(&stream, "404 Not Found", "text/plain", b"File not found", None);
    } else {
        send_response(&stream, "404 Not Found", "text/plain", b"Not Found", None);
    }
}

fn run_server() {
    let local_ip = get_local_ip();
    let pin = get_or_create_pin();
    update_qr_code(&local_ip, &pin);

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
            thread::spawn(move || {
                handle_connection(s, &ip_clone, &pin_clone);
            });
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let ip = get_local_ip();
    let pin = if args.iter().any(|a| a == "--new-pin") {
        generate_new_pin()
    } else {
        get_or_create_pin()
    };
    let qr_path = update_qr_code(&ip, &pin);
    let ddir = get_download_dir().to_string_lossy().to_string();
    let sdir = get_shared_dir().to_string_lossy().to_string();

    if args.iter().any(|a| a == "--serve") {
        run_server();
        return;
    }

    if args.iter().any(|a| a == "--status") {
        println!("{{\"text\":\"\",\"tooltip\":\"OmaSend AirBridge\\nPortal: http://{}:{}\\nPIN: {}\",\"class\":\"normal\"}}", ip, PORT, pin);
        return;
    }

    if args.iter().any(|a| a == "--json") {
        let state = ServerState {
            status: "ACTIVE".to_string(),
            port: PORT,
            local_ip: ip,
            pin,
            download_dir: ddir,
            shared_dir: sdir,
            qr_path,
            total_received: RECEIVED_COUNTER.load(Ordering::SeqCst),
            recent_files: get_recent_files(),
        };
        println!("{}", serde_json::to_string_pretty(&state).unwrap());
        return;
    }

    println!("OMASEND - WIRELESS AIRBRIDGE & CLIPBOARD SENTINEL");
    println!("Portal: http://{}:{} [PIN: {}]", ip, PORT, pin);
    println!("QR: {}", qr_path);
    println!("Downloads: {}", ddir);
}
