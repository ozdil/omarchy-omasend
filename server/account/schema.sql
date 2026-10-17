-- OmaID account registry. Only opaque data: no numbers, IPs, names or device keys.
CREATE TABLE IF NOT EXISTS accounts (
  id          TEXT PRIMARY KEY,   -- hex(HKDF(Argon2id(number), "lookup")): unknown without the number
  pk          TEXT NOT NULL,      -- current account Ed25519 public key (base64url)
  ver         INTEGER NOT NULL,   -- bumped on every write; compare-and-swap guard
  vault       TEXT NOT NULL,      -- AES-256-GCM box under a random key only member devices hold
  keys        TEXT NOT NULL,      -- JSON {kid: key box sealed to one member device}
  reset_pk    TEXT,               -- pending reset (number only, no device left)
  reset_since INTEGER,
  updated     INTEGER NOT NULL    -- unix seconds, for expiring abandoned accounts
);
CREATE TABLE IF NOT EXISTS joins (
  id      TEXT NOT NULL,
  rid     TEXT NOT NULL,
  blob    TEXT NOT NULL,          -- sealed with a key derived from the number
  created INTEGER NOT NULL,
  PRIMARY KEY (id, rid)
);
