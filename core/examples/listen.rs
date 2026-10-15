//! Debug receiver: trusts every peer as Own and logs all events.
//! cargo run --example listen -- <port> <download_dir>
use omasend_core::*;
use std::sync::Arc;

struct Log;
impl NodeCallbacks for Log {
    fn trust(&self, pk: String) -> Trust { eprintln!("trust? {pk}"); Trust::Own }
    fn peer_name(&self, _: String) -> String { String::new() }
    fn incoming_offer(&self, o: IncomingOffer) { eprintln!("offer {o:?}") }
    fn progress(&self, _: String, d: Direction, f: String, done: u64, total: u64) { if done == total { eprintln!("progress {d:?} {f} {done}/{total}") } }
    fn file_received(&self, _: String, _: String, p: String) { eprintln!("received {p}") }
    fn transfer_finished(&self, id: String, d: Direction, ok: bool, e: Option<String>) { eprintln!("finished {id} {d:?} ok={ok} err={e:?}") }
    fn clipboard(&self, _: String, t: String) { eprintln!("clipboard {t}") }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // send mode: listen send <seed-hex-file> <peer_pk> <ip:port> <file>
    if args.get(1).map(String::as_str) == Some("send") {
        let seed = hex_decode(std::fs::read_to_string(&args[2]).unwrap().trim());
        let n = OmaNode::start(seed, "debug-sender".into(), "/tmp/omasend-send-dl".into(), 0, false, Arc::new(Log)).unwrap();
        let r = n.send_files(args[3].clone(), vec![args[4].clone()], vec![args[5].clone()], vec![], String::new());
        eprintln!("send result: {r:?}");
        let c = n.send_clipboard(args[3].clone(), vec![args[4].clone()], "OmaSend QUIC desktop->android".into());
        eprintln!("clipboard result: {c:?}");
        n.shutdown();
        return;
    }
    let port: u16 = args.get(1).and_then(|p| p.parse().ok()).unwrap_or(53319);
    let dir = args.get(2).cloned().unwrap_or_else(|| "/tmp/omasend-listen".into());
    let mut seed = vec![0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let n = OmaNode::start(seed, "listen".into(), dir, port, false, Arc::new(Log)).unwrap();
    eprintln!("id={} port={}", n.endpoint_id(), n.bound_port());
    std::thread::sleep(std::time::Duration::from_secs(600));
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
