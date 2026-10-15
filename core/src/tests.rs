use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct TestCb {
    trust: Mutex<HashMap<String, Trust>>,
    decision: Mutex<Option<bool>>,
    node: Mutex<Option<Arc<OmaNode>>>,
    clipboard: Mutex<Vec<String>>,
    received: Mutex<Vec<String>>,
    resumed_from: Mutex<Option<u64>>,
    offered: AtomicBool,
}

impl TestCb {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            trust: Mutex::new(HashMap::new()),
            decision: Mutex::new(None),
            node: Mutex::new(None),
            clipboard: Mutex::new(vec![]),
            received: Mutex::new(vec![]),
            resumed_from: Mutex::new(None),
            offered: AtomicBool::new(false),
        })
    }
}

impl NodeCallbacks for TestCb {
    fn trust(&self, peer_pk: String) -> Trust {
        *self.trust.lock().unwrap().get(&peer_pk).unwrap_or(&Trust::Unknown)
    }
    fn peer_name(&self, _peer_pk: String) -> String {
        String::new()
    }
    fn incoming_offer(&self, offer: IncomingOffer) {
        self.offered.store(true, Ordering::SeqCst);
        let accept = self.decision.lock().unwrap().unwrap_or(false);
        let node = self.node.lock().unwrap().clone().unwrap();
        std::thread::spawn(move || node.respond(offer.transfer_id, accept));
    }
    fn progress(&self, _id: String, direction: Direction, _f: String, done: u64, _total: u64) {
        if direction == Direction::Receive {
            let mut r = self.resumed_from.lock().unwrap();
            if r.is_none() {
                *r = Some(done);
            }
        }
    }
    fn file_received(&self, _id: String, _peer: String, path: String) {
        self.received.lock().unwrap().push(path);
    }
    fn transfer_finished(&self, _id: String, _d: Direction, _ok: bool, _e: Option<String>) {}
    fn clipboard(&self, _peer: String, text: String) {
        self.clipboard.lock().unwrap().push(text);
    }
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("omasend-core-{}-{}", tag, uuid_like()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn seed() -> Vec<u8> {
    let mut s = vec![0u8; 32];
    getrandom::getrandom(&mut s).unwrap();
    s
}

struct Pair {
    a: Arc<OmaNode>,
    b: Arc<OmaNode>,
    a_cb: Arc<TestCb>,
    b_cb: Arc<TestCb>,
    b_dir: PathBuf,
    b_addr: Vec<String>,
}

fn pair(trust_of_a_on_b: Trust) -> Pair {
    let a_cb = TestCb::new();
    let b_cb = TestCb::new();
    let a_dir = tmp("a");
    let b_dir = tmp("b");
    let a = OmaNode::start(seed(), "A".into(), a_dir.to_string_lossy().into(), 0, false, a_cb.clone()).unwrap();
    let b = OmaNode::start(seed(), "B".into(), b_dir.to_string_lossy().into(), 0, false, b_cb.clone()).unwrap();
    b_cb.trust.lock().unwrap().insert(a.endpoint_id(), trust_of_a_on_b);
    a_cb.trust.lock().unwrap().insert(b.endpoint_id(), Trust::Own);
    *b_cb.node.lock().unwrap() = Some(b.clone());
    let b_addr = vec![format!("127.0.0.1:{}", b.bound_port())];
    Pair { a, b, a_cb, b_cb, b_dir, b_addr }
}

fn random_file(dir: &Path, name: &str, len: usize) -> (PathBuf, Vec<u8>) {
    let mut data = vec![0u8; len];
    getrandom::getrandom(&mut data).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, &data).unwrap();
    (p, data)
}

#[test]
fn own_device_transfer_is_auto_accepted_and_verified() {
    let p = pair(Trust::Own);
    let src = tmp("src");
    let (f1, d1) = random_file(&src, "big.bin", 3 * 1024 * 1024 + 17);
    let (f2, _) = random_file(&src, "empty.txt", 0);
    p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into(), f2.to_string_lossy().into()], vec![], String::new())
        .unwrap();
    assert_eq!(std::fs::read(p.b_dir.join("big.bin")).unwrap(), d1);
    assert_eq!(std::fs::metadata(p.b_dir.join("empty.txt")).unwrap().len(), 0);
    assert!(!p.b_cb.offered.load(Ordering::SeqCst), "own device must not prompt");
    assert_eq!(p.b_cb.received.lock().unwrap().len(), 2);
    p.a.shutdown();
    p.b.shutdown();
}

#[test]
fn paired_device_needs_approval() {
    let p = pair(Trust::Paired);
    let src = tmp("src2");
    let (f1, _) = random_file(&src, "doc.pdf", 1000);
    *p.b_cb.decision.lock().unwrap() = Some(false);
    let err = p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into()], vec![], String::new()).unwrap_err();
    assert!(err.to_string().contains("declined"), "{}", err);
    assert!(p.b_cb.offered.load(Ordering::SeqCst));
    assert!(!p.b_dir.join("doc.pdf").exists());

    *p.b_cb.decision.lock().unwrap() = Some(true);
    p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into()], vec![], String::new()).unwrap();
    assert!(p.b_dir.join("doc.pdf").exists());
    p.a.shutdown();
    p.b.shutdown();
}

#[test]
fn unknown_device_is_refused() {
    let p = pair(Trust::Unknown);
    let src = tmp("src3");
    let (f1, _) = random_file(&src, "x.bin", 10);
    assert!(p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into()], vec![], String::new()).is_err());
    assert!(p.a.send_clipboard(p.b.endpoint_id(), p.b_addr.clone(), "hi".into()).is_err());
    assert!(p.b_cb.clipboard.lock().unwrap().is_empty());
    assert!(!p.b_dir.join("x.bin").exists());
    p.a.shutdown();
    p.b.shutdown();
}

#[test]
fn resume_continues_from_partial_and_detects_corruption() {
    let p = pair(Trust::Own);
    let src = tmp("src4");
    let (f1, d1) = random_file(&src, "movie.mkv", 2 * 1024 * 1024);
    let hash = blake3::hash(&d1).to_hex().to_string();
    let partial = p.b_dir.join(PARTIAL_DIR);
    std::fs::create_dir_all(&partial).unwrap();

    // 1. Valid partial: transfer resumes from the existing half.
    std::fs::write(partial.join(format!("{}.part", hash)), &d1[..1024 * 1024]).unwrap();
    p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into()], vec![], String::new()).unwrap();
    assert_eq!(std::fs::read(p.b_dir.join("movie.mkv")).unwrap(), d1);
    assert!(p.b_cb.resumed_from.lock().unwrap().unwrap() > 1024 * 1024, "receive progress must start after the resumed offset");

    // 2. Corrupted partial: integrity check fails, the bad partial is removed, retry succeeds.
    let mut bad = d1[..1024].to_vec();
    bad[0] ^= 0xff;
    std::fs::write(partial.join(format!("{}.part", hash)), &bad).unwrap();
    let err = p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into()], vec![], String::new()).unwrap_err();
    assert!(err.to_string().contains("integrity"), "{}", err);
    assert!(!partial.join(format!("{}.part", hash)).exists());
    p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into()], vec![], String::new()).unwrap();
    assert_eq!(std::fs::read(p.b_dir.join("movie (1).mkv")).unwrap(), d1);
    p.a.shutdown();
    p.b.shutdown();
}

#[test]
fn clipboard_is_delivered_to_paired_device() {
    let p = pair(Trust::Paired);
    p.a.send_clipboard(p.b.endpoint_id(), p.b_addr.clone(), "merhaba dünya".into()).unwrap();
    assert_eq!(p.b_cb.clipboard.lock().unwrap().as_slice(), ["merhaba dünya".to_string()]);
    let _ = &p.a_cb;
    p.a.shutdown();
    p.b.shutdown();
}

#[test]
fn file_names_are_sanitized() {
    assert_eq!(sanitize_name("../../etc/passwd"), "passwd");
    assert_eq!(sanitize_name("..\\..\\win.ini"), "win.ini");
    assert_eq!(sanitize_name(".bashrc"), "bashrc");
    assert_eq!(sanitize_name("a\u{0}b\nc.txt"), "abc.txt");
    assert_eq!(sanitize_name(""), "file");
    assert_eq!(sanitize_name("..."), "file");
    assert_eq!(sanitize_name("Türkçe şarkı.mp3"), "Türkçe şarkı.mp3");
    let long = format!("{}.txt", "x".repeat(500));
    let s = sanitize_name(&long);
    assert!(s.chars().count() <= 200 && s.ends_with(".txt"));
}

#[test]
fn endpoint_id_matches_protocol_v2_device_key() {
    // Same seed as the protocol v2 cross-language vector.
    let cb = TestCb::new();
    let n = OmaNode::start(vec![7u8; 32], "V".into(), tmp("v").to_string_lossy().into(), 0, false, cb).unwrap();
    assert_eq!(n.endpoint_id(), "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw");
    n.shutdown();
}

#[test]
fn names_override_and_fd_style_paths() {
    let p = pair(Trust::Own);
    let src = tmp("src5");
    let (f1, d1) = random_file(&src, "57", 4096);
    p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into()], vec!["../Fotoğraf 1.jpg".into()], String::new())
        .unwrap();
    assert_eq!(std::fs::read(p.b_dir.join("Fotoğraf 1.jpg")).unwrap(), d1);
    assert!(p.a.send_files(p.b.endpoint_id(), p.b_addr.clone(), vec![f1.to_string_lossy().into()], vec!["a".into(), "b".into()], String::new()).is_err());
    p.a.shutdown();
    p.b.shutdown();
}
