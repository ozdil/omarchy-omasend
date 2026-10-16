//! omasend-core: Phase 2 transport for OmaSend, shared by the desktop engine and the
//! Android app (via UniFFI).
//!
//! * Transport: iroh 1.x (QUIC + TLS 1.3). The endpoint key **is** the device's Ed25519
//!   key from protocol v2, so every connection is end-to-end encrypted and mutually
//!   authenticated by the same key the user paired via QR code.
//! * Access control: connections from keys that are not paired are closed immediately.
//! * Transfers: BLAKE3-verified, resumable (partial files are kept by content hash and
//!   continued from their current length), cancellable, with progress callbacks.
//! * LAN-only by default (no relays, no address publishing). WAN via n0 relays is opt-in.
//!
//! Wire protocol (ALPN `omasend/2`): length-prefixed JSON frames on one bi-directional
//! control stream, raw file bytes on one uni-directional stream per file. See PROTOCOL_V2.md.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey, TransportAddr};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

uniffi::setup_scaffolding!();

pub const ALPN: &[u8] = b"omasend/2";
pub const DEFAULT_PORT: u16 = 53318;
const MAX_FRAME: usize = 1 << 20;
const MAX_FILES: usize = 10_000;
const MAX_FILE_SIZE: u64 = 1 << 40; // 1 TiB
const MAX_CLIPBOARD: usize = 512 * 1024;
const DECISION_TIMEOUT: Duration = Duration::from_secs(120);
const CHUNK: usize = 256 * 1024;
const PARTIAL_DIR: &str = ".omasend-partial";

// ------------------------------------------------------------------ public FFI types

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Trust {
    /// Not paired: the connection is refused.
    Unknown,
    /// QR-paired: transfers need the user's approval, clipboard is allowed.
    Paired,
    /// QR-paired as one of the user's own devices: transfers are auto-accepted.
    Own,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Direction {
    Send,
    Receive,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct OfferedFile {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct IncomingOffer {
    pub transfer_id: String,
    pub peer_pk: String,
    pub peer_name: String,
    pub files: Vec<OfferedFile>,
    pub total_size: u64,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("{msg}")]
    Failed { msg: String },
}

fn fail(msg: impl Into<String>) -> CoreError {
    CoreError::Failed { msg: msg.into() }
}

/// Error text including its source chain, e.g. "connection lost: closed by peer: not paired",
/// so hosts can tell "peer refused" from "network failure".
fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(src) = cur {
        let s = src.to_string();
        if !out.contains(&s) {
            out.push_str(": ");
            out.push_str(&s);
        }
        cur = src.source();
    }
    out
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        fail(e.to_string())
    }
}

/// Implemented by the host app (desktop daemon or Android). Calls arrive on core threads.
#[uniffi::export(with_foreign)]
pub trait NodeCallbacks: Send + Sync {
    fn trust(&self, peer_pk: String) -> Trust;
    fn peer_name(&self, peer_pk: String) -> String;
    /// A paired (not own) device wants to send. Answer with `OmaNode::respond`.
    fn incoming_offer(&self, offer: IncomingOffer);
    fn progress(&self, transfer_id: String, direction: Direction, file_name: String, done: u64, total: u64);
    fn file_received(&self, transfer_id: String, peer_pk: String, path: String);
    fn transfer_finished(&self, transfer_id: String, direction: Direction, ok: bool, error: Option<String>);
    fn clipboard(&self, peer_pk: String, text: String);
}

// ------------------------------------------------------------------ wire messages

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Msg {
    Hello { v: u32, name: String },
    Offer { transfer_id: String, files: Vec<WireFile> },
    Decision { accepted: bool, resume: Vec<u64>, reason: Option<String> },
    FileHeader { transfer_id: String, index: u32, offset: u64 },
    FileDone { index: u32, ok: bool, error: Option<String> },
    Clipboard { text: String },
    Ack { ok: bool, error: Option<String> },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WireFile {
    name: String,
    size: u64,
    blake3: String,
}

async fn write_msg(s: &mut SendStream, m: &Msg) -> Result<(), CoreError> {
    let body = serde_json::to_vec(m).map_err(|e| fail(chain(&e)))?;
    if body.len() > MAX_FRAME {
        return Err(fail("frame too large"));
    }
    s.write_all(&(body.len() as u32).to_be_bytes()).await.map_err(|e| fail(chain(&e)))?;
    s.write_all(&body).await.map_err(|e| fail(chain(&e)))?;
    Ok(())
}

async fn read_msg(r: &mut RecvStream) -> Result<Msg, CoreError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.map_err(|e| fail(format!("read frame: {}", chain(&e))))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(fail("frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|e| fail(format!("read frame: {}", chain(&e))))?;
    serde_json::from_slice(&buf).map_err(|e| fail(format!("bad frame: {e}")))
}

// ------------------------------------------------------------------ helpers

pub fn pk_to_string(pk: &PublicKey) -> String {
    B64.encode(pk.as_bytes())
}

pub fn pk_from_string(s: &str) -> Result<PublicKey, CoreError> {
    let bytes = B64.decode(s.trim()).map_err(|_| fail("invalid public key encoding"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| fail("invalid public key length"))?;
    PublicKey::from_bytes(&arr).map_err(|_| fail("invalid public key"))
}

/// Makes a received file name safe: no directories, no hidden/relative tricks, no control
/// characters, bounded length.
pub fn sanitize_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut out: String = base
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') { '_' } else { c })
        .collect();
    out = out.trim().trim_start_matches('.').to_string();
    if out.is_empty() {
        out = "file".to_string();
    }
    if out.chars().count() > 200 {
        let ext: String = Path::new(&out).extension().and_then(|e| e.to_str()).map(|e| format!(".{}", e)).unwrap_or_default();
        let keep = 200usize.saturating_sub(ext.chars().count());
        out = out.chars().take(keep).collect::<String>() + &ext;
    }
    out
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let p = Path::new(name);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{}", e)).unwrap_or_default();
    for i in 1..10_000 {
        let cand = dir.join(format!("{} ({}){}", stem, i, ext));
        if !cand.exists() {
            return cand;
        }
    }
    dir.join(format!("{}-{}{}", stem, uuid_like(), ext))
}

fn uuid_like() -> String {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).ok();
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(unix)]
pub fn available_space(dir: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(not(unix))]
pub fn available_space(_dir: &Path) -> Option<u64> {
    None
}

async fn blake3_file(path: &Path, limit: Option<u64>) -> Result<(blake3::Hasher, u64), CoreError> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let want = match limit {
            Some(l) => ((l - total) as usize).min(buf.len()),
            None => buf.len(),
        };
        if want == 0 {
            break;
        }
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((h, total))
}

// ------------------------------------------------------------------ node

struct Inner {
    cb: Arc<dyn NodeCallbacks>,
    download_dir: PathBuf,
    my_name: String,
    pending: Mutex<HashMap<String, oneshot::Sender<bool>>>,
    cancels: Mutex<HashMap<String, CancellationToken>>,
}

impl Inner {
    fn cancel_token(&self, id: &str) -> CancellationToken {
        let t = CancellationToken::new();
        self.cancels.lock().unwrap().insert(id.to_string(), t.clone());
        t
    }
    fn drop_token(&self, id: &str) {
        self.cancels.lock().unwrap().remove(id);
    }
}

#[derive(uniffi::Object)]
pub struct OmaNode {
    rt: tokio::runtime::Runtime,
    endpoint: Endpoint,
    router: Mutex<Option<Router>>,
    inner: Arc<Inner>,
}

#[derive(Debug, Clone)]
struct Handler(Arc<Inner>);

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let inner = self.0.clone();
        let peer = pk_to_string(&conn.remote_id());
        let trust = inner.cb.trust(peer.clone());
        if trust == Trust::Unknown {
            conn.close(1u32.into(), b"not paired");
            return Ok(());
        }
        if let Err(e) = serve_connection(inner, conn.clone(), peer, trust).await {
            conn.close(2u32.into(), e.to_string().as_bytes());
        }
        Ok(())
    }
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Inner")
    }
}

async fn serve_connection(inner: Arc<Inner>, conn: Connection, peer: String, trust: Trust) -> Result<(), CoreError> {
    let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| fail(chain(&e)))?;
    let peer_name = match read_msg(&mut recv).await? {
        Msg::Hello { v: 2, name } => name.chars().take(64).collect::<String>(),
        _ => return Err(fail("expected hello")),
    };
    let known_name = inner.cb.peer_name(peer.clone());
    let peer_name = if known_name.is_empty() { peer_name } else { known_name };
    match read_msg(&mut recv).await? {
        Msg::Clipboard { text } => {
            if text.len() > MAX_CLIPBOARD {
                write_msg(&mut send, &Msg::Ack { ok: false, error: Some("clipboard too large".into()) }).await?;
            } else {
                inner.cb.clipboard(peer.clone(), text);
                write_msg(&mut send, &Msg::Ack { ok: true, error: None }).await?;
            }
            linger(&conn, send).await
        }
        Msg::Offer { transfer_id, files } => {
            receive_transfer(inner, conn, send, recv, peer, peer_name, trust, transfer_id, files).await
        }
        _ => Err(fail("unexpected message")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn receive_transfer(
    inner: Arc<Inner>,
    conn: Connection,
    mut send: SendStream,
    _recv: RecvStream,
    peer: String,
    peer_name: String,
    trust: Trust,
    transfer_id: String,
    files: Vec<WireFile>,
) -> Result<(), CoreError> {
    let reject = |reason: &str| Msg::Decision { accepted: false, resume: vec![], reason: Some(reason.to_string()) };
    if files.is_empty() || files.len() > MAX_FILES || transfer_id.len() > 64 {
        write_msg(&mut send, &reject("invalid offer")).await?;
        return linger(&conn, send).await;
    }
    if files.iter().any(|f| f.size > MAX_FILE_SIZE || f.blake3.len() != 64 || !f.blake3.chars().all(|c| c.is_ascii_hexdigit())) {
        write_msg(&mut send, &reject("invalid file entry")).await?;
        return linger(&conn, send).await;
    }
    let total: u64 = files.iter().map(|f| f.size).sum();
    let partial_dir = inner.download_dir.join(PARTIAL_DIR);
    tokio::fs::create_dir_all(&partial_dir).await?;
    if let Some(avail) = available_space(&inner.download_dir) {
        if total.saturating_add(64 << 20) > avail {
            write_msg(&mut send, &reject("insufficient storage")).await?;
            return linger(&conn, send).await;
        }
    }

    let accepted = if trust == Trust::Own {
        true
    } else {
        let (tx, rx) = oneshot::channel();
        inner.pending.lock().unwrap().insert(transfer_id.clone(), tx);
        inner.cb.incoming_offer(IncomingOffer {
            transfer_id: transfer_id.clone(),
            peer_pk: peer.clone(),
            peer_name: peer_name.clone(),
            files: files.iter().map(|f| OfferedFile { name: sanitize_name(&f.name), size: f.size }).collect(),
            total_size: total,
        });
        let decision = tokio::select! {
            r = tokio::time::timeout(DECISION_TIMEOUT, rx) => matches!(r, Ok(Ok(true))),
            _ = conn.closed() => false,
        };
        inner.pending.lock().unwrap().remove(&transfer_id);
        decision
    };
    if !accepted {
        write_msg(&mut send, &reject("declined")).await?;
        return linger(&conn, send).await;
    }

    // Resume: partial data is stored by content hash, so a retried transfer continues.
    let mut resume = Vec::with_capacity(files.len());
    for f in &files {
        let part = partial_dir.join(format!("{}.part", f.blake3.to_lowercase()));
        let len = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0);
        resume.push(if len <= f.size { len } else { 0 });
    }
    write_msg(&mut send, &Msg::Decision { accepted: true, resume: resume.clone(), reason: None }).await?;

    let cancel = inner.cancel_token(&transfer_id);
    let result = async {
        for (index, f) in files.iter().enumerate() {
            let mut uni = tokio::select! {
                s = conn.accept_uni() => s.map_err(|e| fail(chain(&e)))?,
                _ = cancel.cancelled() => return Err(fail("cancelled")),
            };
            match read_msg(&mut uni).await? {
                Msg::FileHeader { transfer_id: tid, index: i, offset } if tid == transfer_id && i as usize == index && offset == resume[index] => {}
                _ => return Err(fail("unexpected file header")),
            }
            let outcome = receive_file(&inner, &cancel, &mut uni, &partial_dir, &transfer_id, f, resume[index], &peer).await;
            let (ok, error) = match &outcome {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            };
            write_msg(&mut send, &Msg::FileDone { index: index as u32, ok, error }).await?;
            outcome?;
        }
        Ok(())
    }
    .await;
    inner.drop_token(&transfer_id);
    let (ok, err) = match &result {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };
    inner.cb.transfer_finished(transfer_id, Direction::Receive, ok, err);
    // Give the sender time to read our final FileDone frame before the connection drops.
    let _ = linger(&conn, send).await;
    result
}

/// Finishes our side and waits (bounded) for the peer to close, so the last frame we sent
/// is delivered instead of being cut off by an immediate connection close.
async fn linger(conn: &Connection, mut send: SendStream) -> Result<(), CoreError> {
    send.finish().ok();
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn receive_file(
    inner: &Inner,
    cancel: &CancellationToken,
    uni: &mut RecvStream,
    partial_dir: &Path,
    transfer_id: &str,
    f: &WireFile,
    offset: u64,
    peer: &str,
) -> Result<(), CoreError> {
    let part = partial_dir.join(format!("{}.part", f.blake3.to_lowercase()));
    let mut hasher = if offset > 0 { blake3_file(&part, Some(offset)).await?.0 } else { blake3::Hasher::new() };
    let mut out = tokio::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&part).await?;
    out.set_len(offset).await?;
    out.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut done = offset;
    let mut buf = vec![0u8; CHUNK];
    let name = sanitize_name(&f.name);
    while done < f.size {
        let want = ((f.size - done) as usize).min(buf.len());
        let n = tokio::select! {
            r = uni.read(&mut buf[..want]) => r.map_err(|e| fail(chain(&e)))?,
            _ = cancel.cancelled() => return Err(fail("cancelled")),
        };
        let Some(n) = n else { return Err(fail("stream ended early")) };
        out.write_all(&buf[..n]).await?;
        hasher.update(&buf[..n]);
        done += n as u64;
        inner.cb.progress(transfer_id.to_string(), Direction::Receive, name.clone(), done, f.size);
    }
    out.flush().await?;
    out.sync_all().await?;
    drop(out);
    if hasher.finalize().to_hex().as_str() != f.blake3.to_lowercase() {
        let _ = tokio::fs::remove_file(&part).await;
        return Err(fail(format!("integrity check failed for {}", name)));
    }
    let dest = unique_path(&inner.download_dir, &name);
    tokio::fs::rename(&part, &dest).await?;
    inner.cb.file_received(transfer_id.to_string(), peer.to_string(), dest.to_string_lossy().to_string());
    Ok(())
}

fn endpoint_addr(peer_pk: &str, addrs: &[String]) -> Result<EndpointAddr, CoreError> {
    let pk = pk_from_string(peer_pk)?;
    let parsed: Vec<TransportAddr> = addrs
        .iter()
        .filter_map(|a| a.parse::<SocketAddr>().ok())
        .map(TransportAddr::Ip)
        .collect();
    Ok(EndpointAddr::from_parts(pk, parsed))
}

#[uniffi::export]
impl OmaNode {
    /// Starts the node. `seed` is the 32-byte Ed25519 device seed from protocol v2, so the
    /// endpoint id equals the device key that was exchanged during QR pairing.
    #[uniffi::constructor]
    pub fn start(
        seed: Vec<u8>,
        my_name: String,
        download_dir: String,
        port: u16,
        wan: bool,
        callbacks: Arc<dyn NodeCallbacks>,
    ) -> Result<Arc<Self>, CoreError> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| fail("seed must be 32 bytes"))?;
        let download_dir = PathBuf::from(download_dir);
        std::fs::create_dir_all(&download_dir)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("omasend-core")
            .build()?;
        let inner = Arc::new(Inner {
            cb: callbacks,
            download_dir,
            my_name: my_name.chars().take(64).collect(),
            pending: Mutex::new(HashMap::new()),
            cancels: Mutex::new(HashMap::new()),
        });
        let (endpoint, router) = rt.block_on(async {
            let secret = SecretKey::from_bytes(&seed);
            let make = |p: u16| {
                let b = if wan {
                    Endpoint::builder(presets::N0)
                } else {
                    Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled)
                };
                b.secret_key(secret.clone())
                    .alpns(vec![ALPN.to_vec()])
                    .bind_addr(SocketAddr::from(([0, 0, 0, 0], p)))
            };
            // Paired peers expect the well-known port, so a briefly busy port (a previous
            // instance still shutting down) is retried for a few seconds before falling back
            // to an ephemeral one.
            let mut endpoint = None;
            if port != 0 {
                for attempt in 0..16 {
                    match make(port).map_err(|e| fail(chain(&e)))?.bind().await {
                        Ok(ep) => {
                            endpoint = Some(ep);
                            break;
                        }
                        Err(_) if attempt < 15 => tokio::time::sleep(Duration::from_millis(500)).await,
                        Err(_) => {}
                    }
                }
            }
            let endpoint = match endpoint {
                Some(ep) => ep,
                None => make(0).map_err(|e| fail(chain(&e)))?.bind().await.map_err(|e| fail(chain(&e)))?,
            };
            let router = Router::builder(endpoint.clone()).accept(ALPN, Handler(inner.clone())).spawn();
            Ok::<_, CoreError>((endpoint, router))
        })?;
        Ok(Arc::new(Self { rt, endpoint, router: Mutex::new(Some(router)), inner }))
    }

    pub fn endpoint_id(&self) -> String {
        pk_to_string(&self.endpoint.id())
    }

    /// Local UDP socket addresses (ip:port) other devices can dial.
    pub fn local_addrs(&self) -> Vec<String> {
        self.endpoint.bound_sockets().iter().map(|a| a.to_string()).collect()
    }

    pub fn bound_port(&self) -> u16 {
        self.endpoint.bound_sockets().first().map(|a| a.port()).unwrap_or(0)
    }

    /// Answer an `incoming_offer`. Unknown ids are ignored.
    pub fn respond(&self, transfer_id: String, accept: bool) {
        if let Some(tx) = self.inner.pending.lock().unwrap().remove(&transfer_id) {
            let _ = tx.send(accept);
        }
    }

    pub fn cancel(&self, transfer_id: String) {
        if let Some(t) = self.inner.cancels.lock().unwrap().get(&transfer_id) {
            t.cancel();
        }
    }

    /// Sends files to a paired device. Blocks until finished; returns the transfer id.
    /// `addrs` are "ip:port" hints (e.g. the last address seen for that device).
    /// `names` optionally overrides the file names (same length as `paths`), e.g. when
    /// Android passes `/proc/self/fd/N` paths for content URIs.
    pub fn send_files(
        &self,
        peer_pk: String,
        addrs: Vec<String>,
        paths: Vec<String>,
        names: Vec<String>,
        transfer_id: String,
    ) -> Result<String, CoreError> {
        let inner = self.inner.clone();
        let endpoint = self.endpoint.clone();
        self.rt.block_on(async move {
            let id = if transfer_id.is_empty() { uuid_like() } else { transfer_id };
            let cancel = inner.cancel_token(&id);
            let r = send_files_inner(&inner, &endpoint, &peer_pk, &addrs, &paths, &names, &id, &cancel).await;
            inner.drop_token(&id);
            let (ok, err) = match &r {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            };
            inner.cb.transfer_finished(id.clone(), Direction::Send, ok, err);
            r.map(|_| id)
        })
    }

    pub fn send_clipboard(&self, peer_pk: String, addrs: Vec<String>, text: String) -> Result<(), CoreError> {
        if text.len() > MAX_CLIPBOARD {
            return Err(fail("clipboard too large"));
        }
        let inner = self.inner.clone();
        let endpoint = self.endpoint.clone();
        self.rt.block_on(async move {
            let conn = tokio::time::timeout(Duration::from_secs(8), endpoint.connect(endpoint_addr(&peer_pk, &addrs)?, ALPN))
                .await
                .map_err(|_| fail("connection timed out"))?
                .map_err(|e| fail(chain(&e)))?;
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| fail(chain(&e)))?;
            write_msg(&mut send, &Msg::Hello { v: 2, name: inner.my_name.clone() }).await?;
            write_msg(&mut send, &Msg::Clipboard { text }).await?;
            let r = match read_msg(&mut recv).await? {
                Msg::Ack { ok: true, .. } => Ok(()),
                Msg::Ack { error, .. } => Err(fail(error.unwrap_or_else(|| "rejected".into()))),
                _ => Err(fail("unexpected reply")),
            };
            send.finish().ok();
            conn.close(0u32.into(), b"done");
            r
        })
    }

    pub fn shutdown(&self) {
        if let Some(router) = self.router.lock().unwrap().take() {
            let _ = self.rt.block_on(router.shutdown());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_files_inner(
    inner: &Inner,
    endpoint: &Endpoint,
    peer_pk: &str,
    addrs: &[String],
    paths: &[String],
    names: &[String],
    transfer_id: &str,
    cancel: &CancellationToken,
) -> Result<(), CoreError> {
    if paths.is_empty() || paths.len() > MAX_FILES {
        return Err(fail("no files"));
    }
    if !names.is_empty() && names.len() != paths.len() {
        return Err(fail("names must match paths"));
    }
    let mut files = Vec::with_capacity(paths.len());
    for (i, p) in paths.iter().enumerate() {
        let path = PathBuf::from(p);
        let meta = tokio::fs::metadata(&path).await?;
        if !meta.is_file() {
            return Err(fail(format!("not a regular file: {}", p)));
        }
        let (h, _) = blake3_file(&path, None).await?;
        let name = match names.get(i) {
            Some(n) if !n.trim().is_empty() => n.clone(),
            _ => path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string(),
        };
        files.push((path, WireFile { name, size: meta.len(), blake3: h.finalize().to_hex().to_string() }));
    }

    let conn = tokio::select! {
        r = tokio::time::timeout(Duration::from_secs(10), endpoint.connect(endpoint_addr(peer_pk, addrs)?, ALPN)) => {
            r.map_err(|_| fail("connection timed out"))?.map_err(|e| fail(chain(&e)))?
        }
        _ = cancel.cancelled() => return Err(fail("cancelled")),
    };
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| fail(chain(&e)))?;
    write_msg(&mut send, &Msg::Hello { v: 2, name: inner.my_name.clone() }).await?;
    write_msg(&mut send, &Msg::Offer { transfer_id: transfer_id.to_string(), files: files.iter().map(|(_, w)| w.clone()).collect() }).await?;

    let resume = tokio::select! {
        m = read_msg(&mut recv) => match m? {
            Msg::Decision { accepted: true, resume, .. } if resume.len() == files.len() => resume,
            Msg::Decision { accepted: false, reason, .. } => return Err(fail(format!("declined: {}", reason.unwrap_or_default()))),
            _ => return Err(fail("unexpected reply")),
        },
        _ = cancel.cancelled() => { conn.close(3u32.into(), b"cancelled"); return Err(fail("cancelled")) }
    };

    let mut buf = vec![0u8; CHUNK];
    for (index, (path, wf)) in files.iter().enumerate() {
        let offset = resume[index].min(wf.size);
        let mut uni = conn.open_uni().await.map_err(|e| fail(chain(&e)))?;
        write_msg(&mut uni, &Msg::FileHeader { transfer_id: transfer_id.to_string(), index: index as u32, offset }).await?;
        let mut f = tokio::fs::File::open(path).await?;
        f.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut done = offset;
        while done < wf.size {
            if cancel.is_cancelled() {
                conn.close(3u32.into(), b"cancelled");
                return Err(fail("cancelled"));
            }
            let want = ((wf.size - done) as usize).min(buf.len());
            let n = f.read(&mut buf[..want]).await?;
            if n == 0 {
                return Err(fail(format!("{} changed while sending", wf.name)));
            }
            uni.write_all(&buf[..n]).await.map_err(|e| fail(chain(&e)))?;
            done += n as u64;
            inner.cb.progress(transfer_id.to_string(), Direction::Send, wf.name.clone(), done, wf.size);
        }
        uni.finish().map_err(|e| fail(chain(&e)))?;
        match read_msg(&mut recv).await? {
            Msg::FileDone { index: i, ok: true, .. } if i as usize == index => {}
            Msg::FileDone { error, .. } => return Err(fail(error.unwrap_or_else(|| "receiver failed".into()))),
            _ => return Err(fail("unexpected reply")),
        }
    }
    send.finish().ok();
    conn.close(0u32.into(), b"done");
    Ok(())
}

#[cfg(test)]
mod tests;
