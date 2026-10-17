// node --test server/account/worker.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto as crypto, createHash } from "node:crypto";
import { handle, idForPk, PREFIX } from "./worker.js";

// Minimal in-memory D1 with the three statements the worker uses.
function fakeDb() {
  const rows = new Map();
  return {
    rows,
    prepare(sql) {
      return {
        bind(...a) {
          return {
            async first() {
              const r = rows.get(a[0]);
              return r ? { ...r } : null;
            },
            async run() {
              let changes = 0;
              if (sql.startsWith("INSERT OR IGNORE")) {
                if (!rows.has(a[0])) { rows.set(a[0], { pk: a[1], ver: 1, blob: a[2], updated: a[3] }); changes = 1; }
              } else if (sql.startsWith("UPDATE accounts SET ver")) {
                const r = rows.get(a[2]);
                if (r && r.ver === a[3]) { r.ver += 1; r.blob = a[0]; r.updated = a[1]; changes = 1; }
              } else if (sql.startsWith("UPDATE accounts SET updated")) {
                const r = rows.get(a[1]); if (r) { r.updated = a[0]; changes = 1; }
              } else if (sql.startsWith("DELETE")) {
                changes = rows.delete(a[0]) ? 1 : 0;
              }
              return { meta: { changes } };
            },
          };
        },
      };
    },
  };
}

const b64 = (u8) => Buffer.from(u8).toString("base64url");
const NOW = 1_800_000_000;

async function account() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pk = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const id = await idForPk(pk);
  const sign = async (msg) => b64(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, new TextEncoder().encode(msg))));
  return { pk, id, sign };
}

async function put(env, a, ver, blob, opts = {}) {
  const ts = opts.ts ?? NOW;
  const h = createHash("sha256").update(blob).digest("hex");
  const sig = opts.sig ?? (await a.sign([PREFIX, "PUT", opts.signId ?? a.id, ver, h, ts].join("|")));
  const req = new Request(`https://x/v1/account/${opts.id ?? a.id}`, { method: "PUT", body: JSON.stringify({ pk: b64(opts.pk ?? a.pk), ver, ts, blob, sig }) });
  return handle(req, env, NOW);
}

const get = (env, id) => handle(new Request(`https://x/v1/account/${id}`), env, NOW);
const BLOB = "A".repeat(60);

test("create, read, update with compare-and-swap", async () => {
  const env = { DB: fakeDb() };
  const a = await account();
  assert.equal((await get(env, a.id)).status, 404);
  let r = await put(env, a, 0, BLOB);
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { ver: 1 });
  assert.deepEqual(await (await get(env, a.id)).json(), { ver: 1, blob: BLOB });
  // Second create and stale writes conflict and return the current record.
  r = await put(env, a, 0, "B".repeat(60));
  assert.equal(r.status, 409);
  assert.equal((await r.json()).blob, BLOB);
  assert.equal((await put(env, a, 1, "C".repeat(60))).status, 200);
  assert.equal((await put(env, a, 1, "D".repeat(60))).status, 409);
});

test("rejects forged, foreign, stale and oversized writes", async () => {
  const env = { DB: fakeDb() };
  const a = await account();
  const b = await account();
  // Someone else's key cannot write a's record.
  assert.equal((await put(env, b, 0, BLOB, { id: a.id, signId: a.id })).status, 403);
  // A signature over a different blob or id does not verify.
  const sig = await a.sign([PREFIX, "PUT", a.id, 0, "00", NOW].join("|"));
  assert.equal((await put(env, a, 0, BLOB, { sig })).status, 403);
  // Replays outside the window are refused.
  assert.equal((await put(env, a, 0, BLOB, { ts: NOW - 301 })).status, 403);
  assert.equal((await put(env, a, 0, "A".repeat(64 * 1024 + 4))).status, 400);
  assert.equal((await put(env, a, 0, "not base64!")).status, 400);
  assert.equal(env.DB.rows.size, 0);
});

test("delete needs the account key", async () => {
  const env = { DB: fakeDb() };
  const a = await account();
  const b = await account();
  await put(env, a, 0, BLOB);
  const del = async (who) =>
    handle(new Request(`https://x/v1/account/${a.id}`, { method: "DELETE", body: JSON.stringify({ pk: b64(who.pk), ts: NOW, sig: await who.sign([PREFIX, "DELETE", a.id, NOW].join("|")) }) }), env, NOW);
  assert.equal((await del(b)).status, 403);
  assert.equal((await del(a)).status, 200);
  assert.equal((await get(env, a.id)).status, 404);
});

test("unknown paths and methods", async () => {
  const env = { DB: fakeDb() };
  assert.equal((await handle(new Request("https://x/v1/account/xyz"), env, NOW)).status, 404);
  assert.equal((await handle(new Request(`https://x/v1/account/${"a".repeat(64)}`, { method: "POST" }), env, NOW)).status, 405);
});
