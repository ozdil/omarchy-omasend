//! OmaID account on the desktop: the host side of `omasend_core::account`.
//!
//! The core does the crypto and the registry protocol; here we provide HTTPS (curl, so
//! the sandboxed daemon needs no TLS stack of its own), keep the secret state in a 0600
//! file, and turn each sync report into trusted own-device keys. Spec: PROTOCOL_V2.md,
//! "Accounts".

use omasend_core::account::{AccountDevice, AccountHttp, AccountReport, AccountStatus, HttpReply};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::devicekey;

pub const DEFAULT_SERVER: &str = "https://id.omaid.app";
const STATE_FILE: &str = "omaid_account";
/// Last report without secrets other than the number: status, devices, pending joins.
const REPORT_FILE: &str = "omaid_report.json";

/// Registry URL: `OMASEND_ACCOUNT_SERVER` (tests, self-hosting) or the default.
pub fn server() -> String {
    std::env::var("OMASEND_ACCOUNT_SERVER").ok().filter(|s| s.starts_with("https://")).unwrap_or_else(|| DEFAULT_SERVER.to_string())
}

/// HTTPS through curl: TLS 1.2+, https only, bounded time and size.
pub struct Curl;

impl AccountHttp for Curl {
    fn request(&self, method: String, url: String, body: String) -> HttpReply {
        let no_net = HttpReply { status: 0, body: String::new() };
        let mut cmd = Command::new("curl");
        cmd.args(["-sS", "--proto", "=https", "--tlsv1.2", "--max-time", "20", "--max-filesize", "1048576", "-X", &method])
            .args(["-H", "content-type: application/json", "-w", "\n%{http_code}"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if method != "GET" {
            cmd.args(["--data-binary", "@-"]);
        }
        cmd.arg(&url);
        let Ok(mut child) = cmd.spawn() else { return no_net };
        if let Some(mut stdin) = child.stdin.take() {
            if method != "GET" {
                let _ = stdin.write_all(body.as_bytes());
            }
        }
        let Ok(out) = child.wait_with_output() else { return no_net };
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let Some((body, code)) = text.rsplit_once('\n') else { return no_net };
        HttpReply { status: code.trim().parse().unwrap_or(0), body: body.to_string() }
    }
}

pub fn load_state(dir: &Path) -> Option<String> {
    crate::read_secure_file(&dir.join(STATE_FILE)).ok().filter(|s| !s.trim().is_empty())
}

pub fn save_state(dir: &Path, state: &str) -> Result<(), String> {
    crate::write_secure_file(&dir.join(STATE_FILE), state)
}

pub fn clear(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(STATE_FILE));
    let _ = std::fs::remove_file(dir.join(REPORT_FILE));
}

pub fn is_member(dir: &Path) -> bool {
    load_report(dir)["status"].as_str() == Some("member")
}

pub fn load_report(dir: &Path) -> serde_json::Value {
    crate::read_secure_file(&dir.join(REPORT_FILE)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(serde_json::Value::Null)
}

fn status_str(s: AccountStatus) -> &'static str {
    match s {
        AccountStatus::Member => "member",
        AccountStatus::Waiting => "waiting",
        AccountStatus::Resetting => "resetting",
        AccountStatus::Removed => "removed",
    }
}

/// Status JSON for the CLI and the panel. The number is included: it is what the user
/// types on their other devices.
pub fn report_json(r: &AccountReport) -> serde_json::Value {
    serde_json::json!({
        "status": status_str(r.status),
        "number": r.number,
        "devices": r.devices.iter().map(|d| serde_json::json!({
            "pk": d.pk,
            "device_id": devicekey::decode_pk(&d.pk).map(|vk| devicekey::device_id_for_pk(vk.as_bytes())).unwrap_or_default(),
            "name": d.name,
            "relay": d.relay,
            "addrs": d.addrs,
        })).collect::<Vec<_>>(),
        "revoked": r.revoked,
        "joins": r.joins.iter().map(|j| serde_json::json!({ "rid": j.rid, "name": j.name, "code": j.code, "suspicious": j.suspicious })).collect::<Vec<_>>(),
        "reset_pending": r.reset_pending,
        "my_code": r.my_code,
        "reset_wait": r.reset_wait,
    })
}

/// What changed for the user since the last report, for desktop notifications.
#[derive(Debug, Default, PartialEq)]
pub struct Changes {
    pub new_devices: Vec<String>,
    pub new_joins: Vec<(String, String)>,
    pub removed_self: bool,
    pub joined: bool,
    pub reset_started: bool,
}

/// Saves a report and mirrors the account's devices into the trust store as own devices.
/// Revoked keys are dropped and refused from then on.
pub fn apply_report(dir: &Path, store: &devicekey::TrustStore, my_pk: &str, r: &AccountReport) -> Result<Changes, String> {
    let prev = load_report(dir);
    let mut ch = Changes::default();
    if r.status == AccountStatus::Removed {
        // Out of the account: forget the devices it gave us.
        for d in prev["devices"].as_array().into_iter().flatten() {
            if let Some(pk) = d["pk"].as_str() {
                if pk != my_pk {
                    store.remove(pk)?;
                }
            }
        }
        ch.removed_self = prev["status"].as_str() == Some("member");
        clear(dir);
        return Ok(ch);
    }
    if !r.state.is_empty() {
        save_state(dir, &r.state)?;
    }
    let json = report_json(r);
    crate::write_secure_file(&dir.join(REPORT_FILE), &json.to_string())?;
    ch.joined = r.status == AccountStatus::Member && prev["status"].as_str() == Some("waiting");
    ch.reset_started = r.reset_pending && prev["reset_pending"].as_bool() != Some(true) && r.status == AccountStatus::Member;
    let seen: HashSet<String> = prev["joins"].as_array().into_iter().flatten().filter_map(|j| j["rid"].as_str().map(str::to_string)).collect();
    ch.new_joins = r.joins.iter().filter(|j| !seen.contains(&j.rid)).map(|j| (j.name.clone(), j.code.clone())).collect();
    if r.status != AccountStatus::Member {
        return Ok(ch);
    }
    for pk in &r.revoked {
        crate::omalink::revoke_key(dir, pk)?;
        store.remove(pk)?;
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    for d in r.devices.iter().filter(|d| d.pk != my_pk) {
        let Some(vk) = devicekey::decode_pk(&d.pk) else { continue };
        let existing = store.get(&d.pk);
        // The first LAN address is a hint; the relay URL is looked up in `addrs_for`.
        let (ip, quic_port) = d
            .addrs
            .iter()
            .filter_map(|a| a.parse::<std::net::SocketAddr>().ok())
            .map(|a| (a.ip().to_string(), a.port()))
            .next()
            .unwrap_or_else(|| (existing.as_ref().map(|k| k.ip.clone()).unwrap_or_default(), existing.as_ref().map(|k| k.quic_port).unwrap_or(0)));
        if existing.as_ref().is_none_or(|k| !k.own_device) {
            ch.new_devices.push(d.name.clone());
        }
        store.upsert(devicekey::TrustedKey {
            pk: d.pk.clone(),
            device_id: devicekey::device_id_for_pk(vk.as_bytes()),
            name: d.name.chars().take(64).collect(),
            ip,
            port: existing.as_ref().map(|k| k.port).unwrap_or(0),
            quic_port,
            own_device: true,
            added_at: existing.as_ref().map(|k| k.added_at).unwrap_or(now),
            last_seen: existing.as_ref().map(|k| k.last_seen).unwrap_or(0),
        })?;
    }
    Ok(ch)
}

/// Extra dial hints for an account device: its relay URL and LAN addresses.
pub fn addrs_for(dir: &Path, pk: &str) -> Vec<String> {
    let r = load_report(dir);
    let Some(d) = r["devices"].as_array().into_iter().flatten().find(|d| d["pk"].as_str() == Some(pk)) else { return vec![] };
    let mut out: Vec<String> = d["addrs"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
    if let Some(relay) = d["relay"].as_str().filter(|r| r.starts_with("https://")) {
        out.push(relay.to_string());
    }
    out
}

/// Our own entry: name, relay and LAN addresses of the QUIC endpoint.
pub fn me(pk: String, name: String, relay: String, lan_ip: &str, quic_port: u16) -> AccountDevice {
    let addrs = lan_ip
        .parse::<std::net::IpAddr>()
        .ok()
        .filter(crate::rendezvous::is_local_network_ip)
        .map(|ip| vec![std::net::SocketAddr::new(ip, quic_port).to_string()])
        .unwrap_or_default();
    AccountDevice { pk, name, relay, addrs, added: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omasend_core::account::JoinRequest;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("omaid-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pk(seed: u8) -> String {
        devicekey::DeviceIdentity::from_seed([seed; 32]).public_b64()
    }

    fn report(status: AccountStatus, devices: Vec<AccountDevice>, revoked: Vec<String>, joins: Vec<JoinRequest>) -> AccountReport {
        AccountReport {
            state: "{\"v\":1}".into(),
            status,
            number: "4539 1488 0343 6467".into(),
            devices,
            revoked,
            joins,
            reset_pending: false,
            my_code: String::new(),
            reset_wait: 0,
        }
    }

    #[test]
    fn report_becomes_own_devices_and_revocations_stick() {
        let d = dir("apply");
        let store = devicekey::TrustStore::new(&d);
        let me = pk(1);
        let phone = AccountDevice { pk: pk(2), name: "phone".into(), relay: "https://euw1-1.relay.iroh.network./".into(), addrs: vec!["192.168.1.7:53318".into()], added: 1 };
        let ch = apply_report(&d, &store, &me, &report(AccountStatus::Member, vec![me_entry(&me), phone.clone()], vec![], vec![])).unwrap();
        assert_eq!(ch.new_devices, vec!["phone".to_string()]);
        let k = store.get(&phone.pk).unwrap();
        assert!(k.own_device);
        assert_eq!((k.ip.as_str(), k.quic_port), ("192.168.1.7", 53318));
        assert!(store.get(&me).is_none(), "never trusts itself");
        assert_eq!(addrs_for(&d, &phone.pk), vec!["192.168.1.7:53318".to_string(), phone.relay.clone()]);
        assert!(is_member(&d));

        // Removed from the account by another device: dropped and refused.
        let ch = apply_report(&d, &store, &me, &report(AccountStatus::Member, vec![me_entry(&me)], vec![phone.pk.clone()], vec![])).unwrap();
        assert!(ch.new_devices.is_empty());
        assert!(store.get(&phone.pk).is_none());
        assert!(crate::omalink::is_revoked(&d, &phone.pk));

        // We were removed: everything the account gave us goes.
        apply_report(&d, &store, &me, &report(AccountStatus::Member, vec![me_entry(&me), AccountDevice { pk: pk(3), ..phone.clone() }], vec![], vec![])).unwrap();
        let ch = apply_report(&d, &store, &me, &report(AccountStatus::Removed, vec![], vec![], vec![])).unwrap();
        assert!(ch.removed_self);
        assert!(store.get(&pk(3)).is_none());
        assert!(load_state(&d).is_none());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn join_requests_notify_once() {
        let d = dir("joins");
        let store = devicekey::TrustStore::new(&d);
        let me = pk(1);
        let j = JoinRequest { rid: "r1".into(), pk: pk(4), name: "tablet".into(), code: "123 456".into(), suspicious: false };
        let r = report(AccountStatus::Member, vec![me_entry(&me)], vec![], vec![j]);
        assert_eq!(apply_report(&d, &store, &me, &r).unwrap().new_joins, vec![("tablet".to_string(), "123 456".to_string())]);
        assert!(apply_report(&d, &store, &me, &r).unwrap().new_joins.is_empty());
        let _ = std::fs::remove_dir_all(d);
    }

    fn me_entry(pk: &str) -> AccountDevice {
        AccountDevice { pk: pk.into(), name: "laptop".into(), relay: String::new(), addrs: vec![], added: 1 }
    }
}
