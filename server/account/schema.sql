-- OmaSend account registry. Only opaque data: no numbers, IPs or names.
CREATE TABLE IF NOT EXISTS accounts (
  id      TEXT PRIMARY KEY,          -- hex(SHA-256("omasend-account-v1 id" || account public key))
  pk      TEXT NOT NULL,             -- account Ed25519 public key (base64url), derived from the number
  ver     INTEGER NOT NULL,          -- bumped on every write; compare-and-swap guard
  blob    TEXT NOT NULL,             -- AES-256-GCM box, only the account's devices can open it
  updated INTEGER NOT NULL           -- unix seconds, for expiring abandoned accounts
);
