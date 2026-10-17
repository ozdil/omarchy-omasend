// OmaSend account registry (Cloudflare Worker + D1).
//
// Stores one end-to-end encrypted box per anonymous account. The account number never
// reaches this server: devices derive an Ed25519 account key and an AES key from it with
// Argon2id, and the record id is a hash of the public key. The server can check that a
// write was signed by the account key and that it does not overwrite a newer version,
// but it cannot read, forge or link records. Spec: PROTOCOL_V2.md, "Account registry".

export const PREFIX = "omasend-account-v1";
export const MAX_BLOB = 64 * 1024;
export const MAX_SKEW = 300;

const enc = new TextEncoder();

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function b64urlDecode(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sha256(bytes) {
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

export async function idForPk(pk) {
  return sha256(new Uint8Array([...enc.encode(PREFIX + " id"), ...pk]));
}

async function verify(pk, msg, sig) {
  try {
    const key = await crypto.subtle.importKey("raw", pk, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, enc.encode(msg));
  } catch {
    return false;
  }
}

async function readBody(req) {
  const len = Number(req.headers.get("content-length") || 0);
  if (len > MAX_BLOB * 2) return null;
  const text = await req.text();
  if (text.length > MAX_BLOB * 2) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" ? v : null;
  } catch {
    return null;
  }
}

/// Checks the account key, the id binding, the clock window and the signature.
async function authorize(id, body, method, extra, now) {
  const pk = b64urlDecode(body.pk);
  const sig = b64urlDecode(body.sig);
  if (!pk || pk.length !== 32 || !sig || sig.length !== 64) return "Bad key or signature";
  if ((await idForPk(pk)) !== id) return "Key does not match account";
  if (!Number.isSafeInteger(body.ts) || Math.abs(now - body.ts) > MAX_SKEW) return "Clock out of range";
  const msg = [PREFIX, method, id, ...extra, body.ts].join("|");
  return (await verify(pk, msg, sig)) ? null : "Bad signature";
}

async function limited(binding, req) {
  if (!binding) return false;
  const key = req.headers.get("cf-connecting-ip") || "unknown";
  const { success } = await binding.limit({ key });
  return !success;
}

export async function handle(req, env, now = Math.floor(Date.now() / 1000)) {
  const url = new URL(req.url);
  const m = url.pathname.match(/^\/v1\/account\/([0-9a-f]{64})$/);
  if (!m) return json(404, { error: "Not found" });
  const id = m[1];

  if (req.method === "GET") {
    if (await limited(env.READS, req)) return json(429, { error: "Slow down" });
    const row = await env.DB.prepare("SELECT ver, blob, updated FROM accounts WHERE id = ?").bind(id).first();
    if (!row) return json(404, { error: "No such account" });
    // Reading keeps an account alive; at most one write a day.
    if (now - row.updated > 86400) {
      await env.DB.prepare("UPDATE accounts SET updated = ? WHERE id = ?").bind(now, id).run();
    }
    return json(200, { ver: row.ver, blob: row.blob });
  }

  if (req.method !== "PUT" && req.method !== "DELETE") return json(405, { error: "Method not allowed" });
  if (await limited(env.WRITES, req)) return json(429, { error: "Slow down" });
  const body = await readBody(req);
  if (!body) return json(400, { error: "Bad request" });

  if (req.method === "DELETE") {
    const err = await authorize(id, body, "DELETE", [], now);
    if (err) return json(403, { error: err });
    await env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(id).run();
    return json(200, { ok: true });
  }

  if (typeof body.blob !== "string" || body.blob.length > MAX_BLOB || !b64urlDecode(body.blob) || body.blob.length < 40) {
    return json(400, { error: "Bad blob" });
  }
  if (!Number.isSafeInteger(body.ver) || body.ver < 0) return json(400, { error: "Bad version" });
  const err = await authorize(id, body, "PUT", [body.ver, await sha256(enc.encode(body.blob))], now);
  if (err) return json(403, { error: err });

  // Compare-and-swap: ver is the version the writer read (0 = create).
  const res =
    body.ver === 0
      ? await env.DB.prepare("INSERT OR IGNORE INTO accounts (id, pk, ver, blob, updated) VALUES (?, ?, 1, ?, ?)")
          .bind(id, body.pk, body.blob, now)
          .run()
      : await env.DB.prepare("UPDATE accounts SET ver = ver + 1, blob = ?, updated = ? WHERE id = ? AND ver = ?")
          .bind(body.blob, now, id, body.ver)
          .run();
  if (res.meta.changes === 1) return json(200, { ver: body.ver + 1 });
  const row = await env.DB.prepare("SELECT ver, blob FROM accounts WHERE id = ?").bind(id).first();
  return json(409, { error: "Version conflict", ver: row ? row.ver : 0, blob: row ? row.blob : null });
}

export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
    } catch {
      return json(500, { error: "Internal error" });
    }
  },
  // Accounts no device has read or written for two years are dropped.
  async scheduled(_event, env) {
    const cutoff = Math.floor(Date.now() / 1000) - 2 * 365 * 24 * 3600;
    await env.DB.prepare("DELETE FROM accounts WHERE updated < ?").bind(cutoff).run();
  },
};
