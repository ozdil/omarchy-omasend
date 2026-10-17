// OmaID account registry (Cloudflare Worker + D1). Spec: PROTOCOL_V2.md, "Accounts".
//
// The account number never reaches this server. Devices derive the record id and a join
// key from it with Argon2id; the vault and every member's key box are encrypted on the
// devices. The server only checks signatures, versions and limits: it cannot read,
// forge or link records, and it keeps no IPs or logs.

export const PREFIX = "omasend-account-v1";
export const MAX_VAULT = 64 * 1024;
export const MAX_KEYS = 64;
export const MAX_KEY_BOX = 1024;
export const MAX_JOINS = 8;
export const MAX_JOIN_BLOB = 2048;
export const TOUCH_EVERY = 30 * 24 * 3600;
export const JOIN_TTL = 15 * 60;
export const MAX_SKEW = 300;
export const RESET_WAIT = 24 * 3600;

const enc = new TextEncoder();

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

const B64URL = /^[A-Za-z0-9_-]+$/;

function b64urlDecode(s) {
  if (typeof s !== "string" || !B64URL.test(s)) return null;
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function verify(pk, msg, sig) {
  try {
    const key = await crypto.subtle.importKey("raw", pk, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, enc.encode(msg));
  } catch {
    return false;
  }
}

async function readJson(req, max) {
  const text = await req.text();
  if (text.length > max) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

function randomHex(n) {
  const b = crypto.getRandomValues(new Uint8Array(n));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function limited(binding, req) {
  if (!binding) return false;
  const { success } = await binding.limit({ key: req.headers.get("cf-connecting-ip") || "unknown" });
  return !success;
}

function validKeys(keys) {
  if (!keys || typeof keys !== "object" || Array.isArray(keys)) return false;
  const entries = Object.entries(keys);
  return (
    entries.length >= 1 &&
    entries.length <= MAX_KEYS &&
    entries.every(([k, v]) => /^[0-9a-f]{32}$/.test(k) && typeof v === "string" && v.length <= MAX_KEY_BOX && B64URL.test(v))
  );
}

function validVault(v) {
  return typeof v === "string" && v.length >= 40 && v.length <= MAX_VAULT && B64URL.test(v);
}

async function getRow(env, id) {
  return env.DB.prepare("SELECT * FROM accounts WHERE id = ?").bind(id).first();
}

async function getRecord(env, id, now) {
  const row = await getRow(env, id);
  if (!row) return null;
  // Reads keep an account alive. Touch it at most monthly, rounded to the day, so the
  // table does not record when members check in.
  if (row.updated < now - TOUCH_EVERY) {
    const day = now - (now % 86400);
    await env.DB.prepare("UPDATE accounts SET updated = ? WHERE id = ? AND updated < ?").bind(day, id, now - TOUCH_EVERY).run();
  }
  const { results } = await env.DB.prepare("SELECT rid, blob FROM joins WHERE id = ? AND created > ? ORDER BY created")
    .bind(id, now - JOIN_TTL)
    .all();
  return {
    ver: row.ver,
    pk: row.pk,
    vault: row.vault,
    keys: JSON.parse(row.keys),
    joins: results.map((j) => ({ rid: j.rid, blob: j.blob })),
    reset: row.reset_pk ? { pk: row.reset_pk, since: row.reset_since } : null,
  };
}

async function dropJoins(env, id, list) {
  if (!Array.isArray(list)) return;
  for (const rid of list.slice(0, MAX_JOINS * 2)) {
    if (typeof rid === "string") await env.DB.prepare("DELETE FROM joins WHERE id = ? AND rid = ?").bind(id, rid).run();
  }
}

// One signed endpoint for every write: {"body": "<json text>", "sig": Ed25519(PREFIX|text)}.
async function signedWrite(env, id, outer, now) {
  if (typeof outer.body !== "string" || outer.body.length > MAX_VAULT + MAX_KEYS * (MAX_KEY_BOX + 40) + 4096) {
    return json(400, { error: "Bad request" });
  }
  let b;
  try {
    b = JSON.parse(outer.body);
  } catch {
    return json(400, { error: "Bad request" });
  }
  const pk = b64urlDecode(b.pk);
  const sig = b64urlDecode(outer.sig);
  if (!pk || pk.length !== 32 || !sig || sig.length !== 64) return json(403, { error: "Bad key or signature" });
  if (b.id !== id) return json(403, { error: "Wrong account" });
  if (!Number.isSafeInteger(b.ts) || Math.abs(now - b.ts) > MAX_SKEW) return json(403, { error: "Clock out of range" });
  if (!(await verify(pk, PREFIX + "|" + outer.body, sig))) return json(403, { error: "Bad signature" });

  const row = await getRow(env, id);
  const isOwner = row && row.pk === b.pk;
  const putFields = () => {
    if (!validVault(b.vault) || !validKeys(b.keys)) return "Bad vault or keys";
    if (b.new_pk !== undefined && (!b64urlDecode(b.new_pk) || b64urlDecode(b.new_pk).length !== 32)) return "Bad new key";
    if (!Number.isSafeInteger(b.ver) || b.ver < 0) return "Bad version";
    return null;
  };

  switch (b.op) {
    case "put": {
      const bad = putFields();
      if (bad) return json(400, { error: bad });
      if (b.ver === 0) {
        if (row) return json(409, { error: "Account exists" });
        await env.DB.prepare("INSERT OR IGNORE INTO accounts (id, pk, ver, vault, keys, updated) VALUES (?, ?, 1, ?, ?, ?)")
          .bind(id, b.pk, b.vault, JSON.stringify(b.keys), now)
          .run();
        return json(200, { ver: 1 });
      }
      if (!row) return json(404, { error: "No such account" });
      if (!isOwner) return json(403, { error: "Not the account key" });
      const res = await env.DB.prepare("UPDATE accounts SET ver = ver + 1, pk = ?, vault = ?, keys = ?, updated = ? WHERE id = ? AND ver = ? AND pk = ?")
        .bind(b.new_pk ?? b.pk, b.vault, JSON.stringify(b.keys), now, id, b.ver, b.pk)
        .run();
      if (res.meta.changes !== 1) return json(409, { error: "Version conflict" });
      await dropJoins(env, id, b.drop_joins);
      return json(200, { ver: b.ver + 1 });
    }
    case "drop_joins":
      if (!isOwner) return json(403, { error: "Not the account key" });
      await dropJoins(env, id, b.drop_joins);
      return json(200, { ok: true });
    case "reset":
      // Anyone holding the number may start a reset; members see it and can cancel.
      if (!row) return json(404, { error: "No such account" });
      if (row.reset_pk) return json(409, { error: "Reset already pending" });
      await env.DB.prepare("UPDATE accounts SET reset_pk = ?, reset_since = ? WHERE id = ? AND reset_pk IS NULL").bind(b.pk, now, id).run();
      return json(200, { ok: true });
    case "cancel_reset":
      if (!isOwner) return json(403, { error: "Not the account key" });
      await env.DB.prepare("UPDATE accounts SET reset_pk = NULL, reset_since = NULL WHERE id = ?").bind(id).run();
      return json(200, { ok: true });
    case "reset_finish": {
      const bad = putFields();
      if (bad || !b.new_pk) return json(400, { error: bad || "Missing new key" });
      if (!row || row.reset_pk !== b.pk || now - row.reset_since < RESET_WAIT) return json(403, { error: "No matured reset for this key" });
      const res = await env.DB.prepare(
        "UPDATE accounts SET ver = ver + 1, pk = ?, vault = ?, keys = ?, reset_pk = NULL, reset_since = NULL, updated = ? WHERE id = ? AND ver = ? AND reset_pk = ?",
      )
        .bind(b.new_pk, b.vault, JSON.stringify(b.keys), now, id, b.ver, b.pk)
        .run();
      if (res.meta.changes !== 1) return json(409, { error: "Version conflict" });
      await env.DB.prepare("DELETE FROM joins WHERE id = ?").bind(id).run();
      return json(200, { ver: b.ver + 1 });
    }
    case "delete":
      if (!isOwner) return json(403, { error: "Not the account key" });
      await env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(id).run();
      await env.DB.prepare("DELETE FROM joins WHERE id = ?").bind(id).run();
      return json(200, { ok: true });
    default:
      return json(400, { error: "Unknown operation" });
  }
}

export async function handle(req, env, now = Math.floor(Date.now() / 1000)) {
  const url = new URL(req.url);
  const m = url.pathname.match(/^\/v1\/account\/([0-9a-f]{64})(\/join)?$/);
  if (!m) return json(404, { error: "Not found" });
  const [, id, join] = m;

  if (req.method === "GET" && !join) {
    if (await limited(env.READS, req)) return json(429, { error: "Slow down" });
    const rec = await getRecord(env, id, now);
    if (!rec) return json(404, { error: "No such account" });
    return json(200, rec);
  }
  if (req.method !== "POST") return json(405, { error: "Method not allowed" });
  if (await limited(env.WRITES, req)) return json(429, { error: "Slow down" });

  if (join) {
    const body = await readJson(req, MAX_JOIN_BLOB + 64);
    if (!body || typeof body.blob !== "string" || body.blob.length < 40 || body.blob.length > MAX_JOIN_BLOB || !B64URL.test(body.blob)) {
      return json(400, { error: "Bad request" });
    }
    if (!(await getRow(env, id))) return json(404, { error: "No such account" });
    await env.DB.prepare("DELETE FROM joins WHERE id = ? AND created <= ?").bind(id, now - JOIN_TTL).run();
    const pending = await env.DB.prepare("SELECT COUNT(*) AS n FROM joins WHERE id = ?").bind(id).first();
    if (pending.n >= MAX_JOINS) return json(429, { error: "Too many pending requests" });
    const rid = randomHex(16);
    await env.DB.prepare("INSERT INTO joins (id, rid, blob, created) VALUES (?, ?, ?, ?)").bind(id, rid, body.blob, now).run();
    return json(200, { rid });
  }

  const outer = await readJson(req, 2 * MAX_VAULT + MAX_KEYS * (MAX_KEY_BOX + 40) + 8192);
  if (!outer) return json(400, { error: "Bad request" });
  return signedWrite(env, id, outer, now);
}

export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
    } catch {
      return json(500, { error: "Internal error" });
    }
  },
  // Expired join requests go right away; accounts untouched for two years are dropped.
  async scheduled(_event, env) {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare("DELETE FROM joins WHERE created <= ?").bind(now - JOIN_TTL).run();
    await env.DB.prepare("DELETE FROM accounts WHERE updated < ?").bind(now - 2 * 365 * 24 * 3600).run();
  },
};
