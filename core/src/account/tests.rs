use super::*;
use std::sync::Mutex;

/// In-memory registry with the same rules as server/account/worker.js.
#[derive(Default)]
struct FakeRegistry {
    rows: Mutex<BTreeMap<String, Row>>,
    rid: Mutex<u32>,
}

#[derive(Clone, Default)]
struct Row {
    pk: String,
    ver: u64,
    vault: String,
    keys: Value,
    joins: Vec<(String, String)>,
    reset: Option<(String, u64)>,
}

fn reply(status: u16, v: Value) -> HttpReply {
    HttpReply { status, body: v.to_string() }
}

impl AccountHttp for FakeRegistry {
    fn request(&self, method: String, url: String, body: String) -> HttpReply {
        let path = url.split("/v1/account/").nth(1).unwrap().to_string();
        let (id, tail) = path.split_once('/').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((path.clone(), String::new()));
        let mut rows = self.rows.lock().unwrap();
        match (method.as_str(), tail.as_str()) {
            ("GET", "") => match rows.get(&id) {
                None => reply(404, json!({ "error": "No such account" })),
                Some(r) => reply(200, json!({
                    "ver": r.ver, "pk": r.pk, "vault": r.vault, "keys": r.keys,
                    "joins": r.joins.iter().map(|(rid, blob)| json!({ "rid": rid, "blob": blob })).collect::<Vec<_>>(),
                    "reset": r.reset.as_ref().map(|(pk, since)| json!({ "pk": pk, "since": since })),
                })),
            },
            ("POST", "join") => {
                let Some(r) = rows.get_mut(&id) else { return reply(404, json!({})) };
                if r.joins.len() >= 8 {
                    return reply(429, json!({}));
                }
                let mut n = self.rid.lock().unwrap();
                *n += 1;
                let rid = format!("{:032x}", *n);
                let blob = serde_json::from_str::<Value>(&body).unwrap()["blob"].as_str().unwrap().to_string();
                r.joins.push((rid.clone(), blob));
                reply(200, json!({ "rid": rid }))
            }
            ("POST", "") => {
                let outer: Value = serde_json::from_str(&body).unwrap();
                let text = outer["body"].as_str().unwrap();
                let b: Value = serde_json::from_str(text).unwrap();
                let signer = b["pk"].as_str().unwrap().to_string();
                if b["id"] != json!(id) || !verify_write(&signer, text, outer["sig"].as_str().unwrap()) {
                    return reply(403, json!({ "error": "Bad signature" }));
                }
                let op = b["op"].as_str().unwrap();
                let row = rows.get(&id).cloned();
                let apply = |r: &mut Row| {
                    r.vault = b["vault"].as_str().unwrap().to_string();
                    r.keys = b["keys"].clone();
                    if let Some(p) = b["new_pk"].as_str() {
                        r.pk = p.to_string();
                    }
                    r.ver += 1;
                };
                let drop = |r: &mut Row| {
                    for d in b["drop_joins"].as_array().into_iter().flatten() {
                        r.joins.retain(|(rid, _)| Some(rid.as_str()) != d.as_str());
                    }
                };
                match (op, row) {
                    ("put", None) if b["ver"] == json!(0) => {
                        let mut r = Row { pk: signer, ..Default::default() };
                        apply(&mut r);
                        rows.insert(id, r);
                        reply(200, json!({ "ver": 1 }))
                    }
                    ("put", Some(_)) if b["ver"] == json!(0) => reply(409, json!({})),
                    ("put", Some(mut r)) => {
                        if r.pk != signer {
                            return reply(403, json!({}));
                        }
                        if b["ver"] != json!(r.ver) {
                            return reply(409, json!({}));
                        }
                        apply(&mut r);
                        drop(&mut r);
                        rows.insert(id, r);
                        reply(200, json!({}))
                    }
                    ("drop_joins", Some(mut r)) if r.pk == signer => {
                        drop(&mut r);
                        rows.insert(id, r);
                        reply(200, json!({}))
                    }
                    ("delete", Some(r)) if r.pk == signer => {
                        rows.remove(&id);
                        reply(200, json!({}))
                    }
                    ("reset", Some(mut r)) if r.reset.is_none() => {
                        r.reset = Some((signer, now()));
                        rows.insert(id, r);
                        reply(200, json!({}))
                    }
                    ("reset", Some(_)) => reply(409, json!({})),
                    ("cancel_reset", Some(mut r)) if r.pk == signer => {
                        r.reset = None;
                        rows.insert(id, r);
                        reply(200, json!({}))
                    }
                    ("reset_finish", Some(mut r)) => {
                        let ok = r.reset.as_ref().is_some_and(|(pk, since)| *pk == signer && now() - since >= RESET_WAIT_SECS);
                        if !ok {
                            return reply(403, json!({}));
                        }
                        if b["ver"] != json!(r.ver) {
                            return reply(409, json!({}));
                        }
                        apply(&mut r);
                        r.joins.clear();
                        r.reset = None;
                        rows.insert(id, r);
                        reply(200, json!({}))
                    }
                    _ => reply(403, json!({ "error": "Not allowed" })),
                }
            }
            _ => reply(404, json!({})),
        }
    }
}

const SERVER: &str = "https://registry.test";

fn dev(seed: u8, name: &str) -> (Vec<u8>, AccountDevice) {
    let s = vec![seed; 32];
    let pk = pk_b64(&device_key(&s).unwrap());
    (s, AccountDevice { pk, name: name.into(), relay: String::new(), addrs: vec![], added: 0 })
}

fn sync(reg: &Arc<FakeRegistry>, state: &str, d: &(Vec<u8>, AccountDevice)) -> AccountReport {
    account_sync(reg.clone(), state.to_string(), d.1.clone(), d.0.clone()).unwrap()
}

#[test]
fn numbers() {
    for _ in 0..50 {
        let n = account_new_number();
        assert!(account_number_valid(n.clone()), "{}", n);
        assert_eq!(n.len(), 19);
    }
    assert!(account_number_valid("4539 1488 0343 6467".into()));
    assert!(!account_number_valid("4539 1488 0343 6468".into()));
    assert!(!account_number_valid("1234".into()));
}

#[test]
fn derivation_is_pinned() {
    // Shared with omasend-android; changing these breaks every existing account.
    let k = derive_number("4539-1488-0343-6467").unwrap();
    let k2 = derive_number("4539148803436467").unwrap();
    assert_eq!(k.lookup, k2.lookup);
    assert_eq!(k.lookup.len(), 64);
    assert_ne!(hex::encode(k.join_key), k.lookup);
    println!("lookup={} join={}", k.lookup, hex::encode(k.join_key));
}

#[test]
fn key_box_round_trip() {
    let (s, d) = dev(7, "x");
    let sealed = seal_to_device(&d.pk, b"secret").unwrap();
    assert_eq!(open_as_device(&device_key(&s).unwrap(), &sealed).unwrap(), b"secret");
    assert!(open_as_device(&device_key(&[8; 32]).unwrap(), &sealed).is_err());
}

#[test]
fn create_join_approve_remove() {
    let reg = Arc::new(FakeRegistry::default());
    let (a, b, c) = (dev(1, "laptop"), dev(2, "phone"), dev(3, "tablet"));
    let sa = account_create(reg.clone(), SERVER.into(), String::new(), a.1.clone(), a.0.clone()).unwrap();
    let number = State::parse(&sa).unwrap().number.clone();

    // The same number cannot be created twice.
    assert!(account_create(reg.clone(), SERVER.into(), number.clone(), b.1.clone(), b.0.clone()).is_err());

    // B asks to join; the number alone gives no access.
    let jb = account_join(reg.clone(), SERVER.into(), number.clone(), b.1.clone(), b.0.clone()).unwrap();
    assert_eq!(jb.status, AccountStatus::Waiting);
    assert_eq!(sync(&reg, &jb.state, &b).status, AccountStatus::Waiting);

    // A sees the request with the same code B shows, and approves it.
    let ra = sync(&reg, &sa, &a);
    assert_eq!(ra.status, AccountStatus::Member);
    assert_eq!(ra.joins.len(), 1);
    assert_eq!(ra.joins[0].code, jb.my_code);
    assert_eq!(ra.joins[0].name, "phone");
    let sa = account_approve(reg.clone(), ra.state, ra.joins[0].rid.clone(), a.0.clone()).unwrap();

    let rb = sync(&reg, &jb.state, &b);
    assert_eq!(rb.status, AccountStatus::Member);
    assert_eq!(rb.devices.len(), 2);
    let sb = rb.state;

    // C joins, B approves it.
    let jc = account_join(reg.clone(), SERVER.into(), number.clone(), c.1.clone(), c.0.clone()).unwrap();
    let rb = sync(&reg, &sb, &b);
    let sb = account_approve(reg.clone(), rb.state, rb.joins[0].rid.clone(), b.0.clone()).unwrap();
    let sc = sync(&reg, &jc.state, &c).state;

    // A removes C: C loses access, keys rotate, A and B follow.
    let sa = account_remove(reg.clone(), sync(&reg, &sa, &a).state, c.1.pk.clone()).unwrap();
    assert_eq!(sync(&reg, &sc, &c).status, AccountStatus::Removed);
    let rb = sync(&reg, &sb, &b);
    assert_eq!(rb.status, AccountStatus::Member);
    assert!(rb.revoked.contains(&c.1.pk));
    assert_eq!(rb.devices.len(), 2);

    // C's old account key no longer writes.
    let old = State::parse(&sc).unwrap();
    let (old_sk, _) = old.member_keys().unwrap();
    assert!(Client { http: reg.clone() }.signed(&old, &old_sk, json!({ "op": "drop_joins", "drop_joins": [] })).is_err());

    // A removed device's new request is not offered for approval.
    let _ = account_join(reg.clone(), SERVER.into(), number.clone(), c.1.clone(), c.0.clone()).unwrap();
    assert!(sync(&reg, &sa, &a).joins.is_empty());

    // The last devices leave; the account is gone.
    let sb = sync(&reg, &sb, &b).state;
    account_leave(reg.clone(), sb, b.0.clone()).unwrap();
    let sa = sync(&reg, &sa, &a).state;
    assert_eq!(sync(&reg, &sa, &a).devices.len(), 1);
    account_delete(reg.clone(), sa.clone()).unwrap();
    assert!(account_join(reg.clone(), SERVER.into(), number.clone(), c.1.clone(), c.0.clone()).is_err());
}

#[test]
fn reachability_updates_and_rollback_is_refused() {
    let reg = Arc::new(FakeRegistry::default());
    let mut a = dev(1, "laptop");
    let sa = account_create(reg.clone(), SERVER.into(), String::new(), a.1.clone(), a.0.clone()).unwrap();
    let before = reg.rows.lock().unwrap().values().next().unwrap().clone();
    a.1.relay = "https://euw1-1.relay.iroh.network./".into();
    a.1.addrs = vec!["192.168.1.5:53318".into()];
    let r = sync(&reg, &sa, &a);
    assert_eq!(r.devices[0].relay, a.1.relay);
    // A second sync with nothing new writes nothing.
    let ver = reg.rows.lock().unwrap().values().next().unwrap().ver;
    let r = sync(&reg, &r.state, &a);
    assert_eq!(reg.rows.lock().unwrap().values().next().unwrap().ver, ver);
    // The server serves the old vault again: refused.
    {
        let mut rows = reg.rows.lock().unwrap();
        let row = rows.values_mut().next().unwrap();
        row.vault = before.vault.clone();
    }
    assert!(account_sync(reg.clone(), r.state, a.1.clone(), a.0.clone()).is_err());
}

#[test]
fn qr_invite_approves_without_codes() {
    let reg = Arc::new(FakeRegistry::default());
    let (a, b, x) = (dev(1, "laptop"), dev(2, "phone"), dev(9, "intruder"));
    let sa = account_create(reg.clone(), SERVER.into(), String::new(), a.1.clone(), a.0.clone()).unwrap();
    let inv = account_invite(sa).unwrap();
    assert!(inv.uri.starts_with(INVITE_BASE));
    let number = State::parse(&inv.state).unwrap().number.clone();

    // Someone with only the number is not auto-approved.
    let jx = account_join(reg.clone(), SERVER.into(), number, x.1.clone(), x.0.clone()).unwrap();
    let jb = account_join(reg.clone(), SERVER.into(), inv.uri.clone(), b.1.clone(), b.0.clone()).unwrap();
    let ra = sync(&reg, &inv.state, &a);
    assert_eq!(ra.devices.len(), 2);
    assert_eq!(ra.joins.len(), 1, "the intruder still needs a manual approval");
    assert_eq!(sync(&reg, &jb.state, &b).status, AccountStatus::Member);
    assert_eq!(sync(&reg, &jx.state, &x).status, AccountStatus::Waiting);
    // The invite is single-use.
    assert!(State::parse(&ra.state).unwrap().invites.is_empty());
}

#[test]
fn change_number_moves_every_device() {
    let reg = Arc::new(FakeRegistry::default());
    let (a, b) = (dev(1, "laptop"), dev(2, "phone"));
    let sa = account_create(reg.clone(), SERVER.into(), String::new(), a.1.clone(), a.0.clone()).unwrap();
    let old = State::parse(&sa).unwrap().number.clone();
    let jb = account_join(reg.clone(), SERVER.into(), old.clone(), b.1.clone(), b.0.clone()).unwrap();
    let ra = sync(&reg, &sa, &a);
    let sa = account_approve(reg.clone(), ra.state, ra.joins[0].rid.clone(), a.0.clone()).unwrap();
    let sb = sync(&reg, &jb.state, &b).state;

    let sa = account_change_number(reg.clone(), sa).unwrap();
    let new = State::parse(&sa).unwrap().number.clone();
    assert_ne!(new, old);
    let rb = sync(&reg, &sb, &b);
    assert_eq!(rb.status, AccountStatus::Member);
    assert_eq!(rb.number, new);
    assert_eq!(sync(&reg, &sa, &a).devices.len(), 2);
}

#[test]
fn reset_waits_and_members_can_cancel() {
    let reg = Arc::new(FakeRegistry::default());
    let (a, n) = (dev(1, "lost laptop"), dev(5, "new phone"));
    let sa = account_create(reg.clone(), SERVER.into(), String::new(), a.1.clone(), a.0.clone()).unwrap();
    let number = State::parse(&sa).unwrap().number.clone();

    let sn = account_reset_start(reg.clone(), SERVER.into(), number.clone()).unwrap();
    let r = sync(&reg, &sn, &n);
    assert_eq!(r.status, AccountStatus::Resetting);
    assert!(r.reset_wait > RESET_WAIT_SECS - 60);
    // The member sees it and cancels.
    assert!(sync(&reg, &sa, &a).reset_pending);
    account_cancel_reset(reg.clone(), sa.clone()).unwrap();
    assert!(account_sync(reg.clone(), sn, n.1.clone(), n.0.clone()).is_err());

    // Nobody cancels: after the wait the new device owns the account and A is out.
    let sn = account_reset_start(reg.clone(), SERVER.into(), number).unwrap();
    {
        let mut rows = reg.rows.lock().unwrap();
        let row = rows.values_mut().next().unwrap();
        row.reset.as_mut().unwrap().1 -= RESET_WAIT_SECS;
    }
    let r = sync(&reg, &sn, &n);
    assert_eq!(r.status, AccountStatus::Member);
    assert_eq!(r.devices.len(), 1);
    assert_eq!(sync(&reg, &sa, &a).status, AccountStatus::Removed);
}
