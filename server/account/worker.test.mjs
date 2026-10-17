// node --test server/account/worker.test.mjs  (Node 22+, uses node:sqlite as D1)
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { webcrypto as crypto } from "node:crypto";
import { handle, PREFIX, RESET_WAIT, JOIN_TTL } from "./worker.js";

function d1() {
  const db = new DatabaseSync(":memory:");
  db.exec(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
  return {
    db,
    prepare(sql) {
      const st = db.prepare(sql);
      return {
        bind(...a) {
          return {
            first: async () => st.get(...a) ?? null,
            all: async () => ({ results: st.all(...a) }),
            run: async () => ({ meta: { changes: Number(st.run(...a).changes) } }),
          };
        },
      };
    },
  };
}

const b64 = (u8) => Buffer.from(u8).toString("base64url");
const ID = "ab".repeat(32);
const VAULT = "V".repeat(60);
const KEYS = { ["0".repeat(32)]: "K".repeat(80) };
let NOW = 1_800_000_000;

async function key() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pk = b64(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
  return { pk, kp };
}

async function write(env, k, fields, opts = {}) {
  const body = JSON.stringify({ id: opts.id ?? ID, ts: opts.ts ?? NOW, pk: k.pk, ...fields });
  const sig = b64(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, k.kp.privateKey, new TextEncoder().encode(PREFIX + "|" + (opts.signed ?? body)))));
  return handle(new Request(`https://x/v1/account/${ID}`, { method: "POST", body: JSON.stringify({ body, sig }) }), env, NOW);
}

const get = (env) => handle(new Request(`https://x/v1/account/${ID}`), env, NOW);
const join = (env, blob = "J".repeat(60)) => handle(new Request(`https://x/v1/account/${ID}/join`, { method: "POST", body: JSON.stringify({ blob }) }), env, NOW);
const put = (env, k, ver, extra = {}) => write(env, k, { op: "put", ver, vault: VAULT, keys: KEYS, ...extra });

test("create, read, compare-and-swap, rotate", async () => {
  const env = { DB: d1() };
  const a = await key();
  assert.equal((await get(env)).status, 404);
  assert.equal((await put(env, a, 0)).status, 200);
  const rec = await (await get(env)).json();
  assert.deepEqual(rec, { ver: 1, pk: a.pk, vault: VAULT, keys: KEYS, joins: [], reset: null });
  assert.equal((await put(env, a, 0)).status, 409, "number already taken");
  assert.equal((await put(env, a, 1)).status, 200);
  assert.equal((await put(env, a, 1)).status, 409, "stale version");
  // Rotation hands the account to a new key; the old one stops working.
  const b = await key();
  assert.equal((await put(env, a, 2, { new_pk: b.pk })).status, 200);
  assert.equal((await put(env, a, 3)).status, 403);
  assert.equal((await put(env, b, 3)).status, 200);
});

test("forged, replayed, foreign and oversized writes are refused", async () => {
  const env = { DB: d1() };
  const a = await key();
  const b = await key();
  await put(env, a, 0);
  assert.equal((await put(env, b, 1)).status, 403, "someone else's key");
  assert.equal((await write(env, a, { op: "put", ver: 1, vault: VAULT, keys: KEYS }, { signed: "something else" })).status, 403);
  assert.equal((await write(env, a, { op: "put", ver: 1, vault: VAULT, keys: KEYS }, { ts: NOW - 301 })).status, 403);
  assert.equal((await write(env, a, { op: "put", ver: 1, vault: VAULT, keys: KEYS }, { id: "cd".repeat(32) })).status, 403);
  assert.equal((await put(env, a, 1, { vault: "V".repeat(64 * 1024 + 1) })).status, 400);
  assert.equal((await put(env, a, 1, { keys: {} })).status, 400);
  assert.equal((await put(env, a, 1, { keys: { "not-hex": "K".repeat(80) } })).status, 400);
  assert.equal((await write(env, a, { op: "nope" })).status, 400);
  assert.equal((await (await get(env)).json()).ver, 1);
});

test("join requests: pending list, cap, expiry, drop", async () => {
  const env = { DB: d1() };
  const a = await key();
  assert.equal((await join(env)).status, 404, "no account yet");
  await put(env, a, 0);
  assert.equal((await join(env, "bad blob!")).status, 400);
  const rids = [];
  for (let i = 0; i < 8; i++) rids.push((await (await join(env)).json()).rid);
  assert.equal((await join(env)).status, 429);
  assert.equal((await (await get(env)).json()).joins.length, 8);
  assert.equal((await write(env, a, { op: "drop_joins", drop_joins: rids.slice(0, 3) })).status, 200);
  assert.equal((await (await get(env)).json()).joins.length, 5);
  // An approval (put with drop_joins) removes the handled request.
  assert.equal((await put(env, a, 1, { drop_joins: [rids[3]] })).status, 200);
  assert.equal((await (await get(env)).json()).joins.length, 4);
  NOW += JOIN_TTL + 1;
  assert.equal((await (await get(env)).json()).joins.length, 0, "expired requests are hidden");
  assert.equal((await join(env)).status, 200, "and no longer count against the cap");
});

test("reset waits a day and members can cancel it", async () => {
  const env = { DB: d1() };
  const a = await key();
  const r = await key();
  await put(env, a, 0);
  assert.equal((await write(env, r, { op: "reset" })).status, 200);
  assert.equal((await write(env, r, { op: "reset" })).status, 409);
  assert.deepEqual((await (await get(env)).json()).reset, { pk: r.pk, since: NOW });
  const fresh = await key();
  const finish = () => write(env, r, { op: "reset_finish", ver: 1, vault: VAULT, keys: KEYS, new_pk: fresh.pk });
  assert.equal((await finish()).status, 403, "too early");
  assert.equal((await write(env, r, { op: "cancel_reset" })).status, 403, "only the account key cancels");
  assert.equal((await write(env, a, { op: "cancel_reset" })).status, 200);
  assert.equal((await (await get(env)).json()).reset, null);

  assert.equal((await write(env, r, { op: "reset" })).status, 200);
  await join(env);
  NOW += RESET_WAIT;
  assert.equal((await finish()).status, 200);
  const rec = await (await get(env)).json();
  assert.equal(rec.pk, fresh.pk);
  assert.equal(rec.reset, null);
  assert.equal(rec.joins.length, 0);
  assert.equal((await put(env, a, 2)).status, 403, "the old key is out");
});

test("delete needs the account key; unknown routes", async () => {
  const env = { DB: d1() };
  const a = await key();
  const b = await key();
  await put(env, a, 0);
  assert.equal((await write(env, b, { op: "delete" })).status, 403);
  assert.equal((await write(env, a, { op: "delete" })).status, 200);
  assert.equal((await get(env)).status, 404);
  assert.equal((await handle(new Request("https://x/v1/account/xyz"), env, NOW)).status, 404);
  assert.equal((await handle(new Request(`https://x/v1/account/${ID}`, { method: "PUT" }), env, NOW)).status, 405);
});

test("reads keep an account alive, touched at most monthly", async () => {
  const env = { DB: d1() };
  const a = await key();
  assert.equal((await put(env, a, 0)).status, 200);
  const updated = () => env.DB.db.prepare("SELECT updated FROM accounts").get().updated;
  const t0 = updated();
  NOW += 10 * 24 * 3600;
  await get(env);
  assert.equal(updated(), t0, "recent accounts are not touched");
  NOW += 30 * 24 * 3600;
  await get(env);
  assert.equal(updated(), NOW - (NOW % 86400), "touched, rounded to the day");
});
