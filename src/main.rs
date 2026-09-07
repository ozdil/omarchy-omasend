use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

const PORT: u16 = 8844;

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerState {
    pub status: String,
    pub port: u16,
    pub local_ip: String,
    pub download_dir: String,
    pub total_received: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusOutput {
    pub text: String,
    pub tooltip: String,
    pub class: String,
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

fn get_download_dir() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = Path::new(&home).join("Downloads/omasend");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn handle_connection(mut stream: TcpStream, ip: &str) {
    let mut buffer = [0u8; 8192];
    let n = match stream.read(&mut buffer) {
        Ok(bytes) if bytes > 0 => bytes,
        _ => return,
    };
    let req = String::from_utf8_lossy(&buffer[..n]);
    let first_line = req.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    if method == "GET" && path == "/" {
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OmaSend AirBridge</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0a0e14; color: #e5e7eb; max-width: 600px; margin: 40px auto; padding: 20px; }}
h1 {{ font-size: 20px; letter-spacing: 1.5px; text-transform: uppercase; border-bottom: 2px solid #38bdf8; padding-bottom: 8px; }}
.card {{ background: #111827; border: 1px solid #1f2937; padding: 20px; margin-top: 20px; border-radius: 4px; }}
button, input[type=submit] {{ background: #38bdf8; color: #000; border: none; padding: 10px 16px; font-weight: bold; cursor: pointer; border-radius: 2px; }}
textarea {{ width: 100%; height: 80px; background: #1f2937; border: 1px solid #374151; color: #fff; padding: 8px; box-sizing: border-box; }}
</style>
</head>
<body>
<h1>OMASEND - WIRELESS AIRBRIDGE</h1>
<div class="card">
<p>Connected to <strong>{}</strong> on port {}</p>
<form method="POST" action="/upload" enctype="multipart/form-data">
<p><input type="file" name="file" required></p>
<p><input type="submit" value="Send File to Omarchy PC"></p>
</form>
</div>
<div class="card">
<form method="POST" action="/clipboard">
<p><textarea name="text" placeholder="Type text to paste into PC clipboard..."></textarea></p>
<p><input type="submit" value="Send to PC Clipboard"></p>
</form>
</div>
</body>
</html>"#,
            ip, PORT
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if method == "POST" && path == "/clipboard" {
        // Read body text and write via wl-copy
        if let Some(body_start) = req.find("\r\n\r\n") {
            let body = &req[body_start + 4..];
            let clean_text = if let Some(pos) = body.find("text=") {
                &body[pos + 5..]
            } else {
                body
            };
            let decoded = clean_text.replace('+', " ");
            let _ = Command::new("wl-copy").arg(decoded).spawn();
        }
        let msg = "HTTP/1.1 303 See Other\r\nLocation: /\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(msg.as_bytes());
    } else {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK";
        let _ = stream.write_all(resp.as_bytes());
    }
}

fn run_server() {
    let local_ip = get_local_ip();
    let addr = format!("0.0.0.0:{}", PORT);
    if let Ok(listener) = TcpListener::bind(&addr) {
        println!("OmaSend listening on http://{}:{}", local_ip, PORT);
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                let ip_clone = local_ip.clone();
                thread::spawn(move || {
                    handle_connection(s, &ip_clone);
                });
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let ip = get_local_ip();
    let ddir = get_download_dir().to_string_lossy().to_string();

    if args.iter().any(|a| a == "--serve") {
        run_server();
        return;
    }

    if args.iter().any(|a| a == "--status") {
        let text = format!("OMASEND: {}", if ip != "127.0.0.1" { "READY" } else { "IDLE" });
        let tooltip = format!(
            "OmaSend - Local AirBridge & Clipboard Share\nIP: {}:{}\nSave Path: {}\nEngine: Native Rust",
            ip, PORT, ddir
        );
        let out = StatusOutput {
            text,
            tooltip,
            class: "normal".to_string(),
        };
        println!("{}", serde_json::to_string(&out).unwrap());
        return;
    }

    if args.iter().any(|a| a == "--json") {
        let state = ServerState {
            status: "READY".to_string(),
            port: PORT,
            local_ip: ip,
            download_dir: ddir,
            total_received: 0,
        };
        println!("{}", serde_json::to_string_pretty(&state).unwrap());
        return;
    }

    println!("OMASEND - WIRELESS AIRBRIDGE & CLIPBOARD SENTINEL");
    println!("Portal: http://{}:{}", ip, PORT);
    println!("Save Path: {}", ddir);
}
