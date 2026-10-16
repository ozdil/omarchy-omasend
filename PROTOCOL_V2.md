# OmaSend Protocol v2 (Phase 1): device keys, QR pairing, signed requests

Status: implemented in `omarchy-omasend` (`src/devicekey.rs`) and `omasend-android`
(`crypto/DeviceKey.kt`). Both implementations are checked against the same test vector.

## Why

OmaID is broadcast in discovery beacons and request headers, so it cannot prove who
sent a request (REPORT_v2 V2-SEC-01/02). v2 gives every device an Ed25519 key pair and
trusts only keys that were exchanged in person, via a QR code.

OmaID remains as a display/grouping label. It no longer grants any trust.

## Encoding

- `b64url`: base64url **without** padding (RFC 4648 §5).
- `hex`: lowercase.
- Device ID: first 8 bytes of `SHA-256(pk)`, uppercase hex, `XXXX-XXXX-XXXX-XXXX`.

## Identity

Each device creates a random 32-byte Ed25519 seed on first run:

- Desktop: `~/.local/state/omarchy/omasend/device_ed25519.key` (hex, mode 0600).
- Android: app-private storage, encrypted with an Android Keystore AES key.

## Pairing

The **responder** (usually the desktop) creates an offer, valid for 5 minutes and usable once:

```
omasend://pair?v=2&pk=<b64url R_pk>&s=<b64url 32-byte secret>&h=<ip>&p=<port>&n=<urlenc name>&o=<0|1>&q=<quic port>
```

- `h`, `p`: address of the responder's HTTP endpoint. The initiator refuses a link whose `h` is
  not a private (RFC 1918 / unique-local) or link-local address, so a QR code on a web page or in
  a chat cannot make it connect elsewhere.
- `q`: UDP port of the responder's QUIC endpoint (Phase 2). `0` or missing = default `53318`.
- `o=1` means "the responder will trust the new device as one of its own devices". It describes
  the **responder's** trust only. That trust level enables auto-accept of transfers.

Each side chooses its own trust level for the other. The initiator never copies `o`: it stores
the responder as `Paired` unless its own user explicitly chooses "my device"
(`omasend-engine --pair-with <uri> --own`, or the "My device" option in the panel's scan
confirmation). The desktop panel shows the responder's name and device ID and asks for
confirmation before pairing with a QR code found on screen.

The **initiator** scans the QR code and sends:

```
POST /api/v2/pair
{ "pk":   b64url(I_pk),
  "name": "<initiator name>",
  "mac":  hex(HMAC-SHA256(secret, "omasend-pair-v2|" + R_pk + "|" + I_pk)),
  "sig":  b64url(Ed25519_I("omasend-pair-v2|" + R_pk + "|" + I_pk + "|" + mac)),
  "quic_port": <initiator's QUIC UDP port, 0 = default> }
```

The responder checks:

1. An unexpired offer exists whose secret produces the same `mac`.
2. `sig` verifies with `I_pk`.

If both pass, it consumes the offer, stores `I_pk`, and replies:

```
200 { "pk": b64url(R_pk), "name": "...", "device_id": "...",
      "sig": b64url(Ed25519_R(same transcript)), "quic_port": <responder's QUIC UDP port> }
```

The initiator checks that `pk` equals the key from the QR code, then verifies `sig`.

Each side stores the other's `quic_port` with the key. The responder stores the initiator's
address from the TCP source of the request; a loopback source (the WAN tunnel) is not stored.

### Failure policy

- The offer secret is 256 bits, so guessing it is not a practical attack. The limits only
  stop one host from hammering the endpoint or invalidating the user's QR code.
- Failed `POST /api/v2/pair` attempts are limited **per source address**: 5 failures within
  60 s block that address for 60 s (`429`). Behind the WAN tunnel the address is the client
  address reported in `Cf-Connecting-Ip`.
- Backstop: after 50 failed attempts from any address, every open offer is burned.
- `POST /api/v2/pair` is refused (`403`) while visibility is `OFF`.

## Signed requests

Every request between paired devices carries four headers:

```
X-OmaSend-Pk:    b64url(pk)
X-OmaSend-Ts:    unix seconds
X-OmaSend-Nonce: 16 random bytes, hex (32 chars)
X-OmaSend-Sig:   b64url(Ed25519(canonical))
```

The signed string is:

```
canonical = "omasend-v2\n" + METHOD + "\n" + path[?query exactly as sent] + "\n" + ts + "\n" + nonce + "\n" + body_tag
body_tag  = hex(SHA-256(body))        for JSON / empty bodies
          = "stream:" + Content-Length for POST /api/p2p/upload
```

The receiver accepts a request only if all of these hold:

- `|ts - now| <= 300` seconds.
- The nonce has not been seen before (cache kept for 601 seconds).
- The key is in the trust store.
- The signature verifies.

### Receiver policy

| Case | Result |
|---|---|
| Valid signature, paired as own device | Transfers are auto-accepted. Clipboard is allowed. |
| Valid signature, paired, not own device | Transfers need approval. Clipboard is allowed. |
| No headers, or a key that was never paired | Legacy rules: approval required; clipboard needs legacy pairing. |
| Known key with a bad signature, stale timestamp or replayed nonce | `401` |
| Upload for a transfer opened by a verified key | Must be signed by the same key, otherwise `401` |

On every successful verification, the receiver updates the stored IP for that key. This
handles DHCP address changes without trusting unauthenticated beacons. A loopback source
address (requests through the WAN tunnel) only updates `last_seen`, never the stored IP.

### Visibility

| Mode | Unsigned / unknown-key `POST /api/p2p/request` |
|---|---|
| `KNOWN` (default) | Refused (`403`) unless the OmaID belongs to a confirmed legacy pairing. |
| `EVERYONE` (10 minutes, then back to `KNOWN`) | Accepted; needs the user's approval. |
| `OFF` | Every pairing, transfer and clipboard endpoint is refused. |

Requests signed by a paired key are accepted in `KNOWN` and `EVERYONE`.

The desktop keeps a single pending-transfer slot. A request from a verified sender (signed by a
paired key, or a QUIC offer) may replace a request from an unverified sender that is still
waiting for approval; otherwise a second request gets `409` with `Retry-After`. An accepted
HTTP transfer stays open while uploads keep arriving (10 minutes idle). Polling
`GET /api/p2p/decision?token=` returns `PENDING`, `ACCEPTED`, `REJECTED`, `EXPIRED` or `404`.

### Clipboard

| Sender | Receiving | Automatic sending (clipboard watcher) |
|---|---|---|
| Own device (QR) | Accepted, no prompt (QUIC; signed HTTP from older apps) | Yes, QUIC only |
| Paired, not own (QR) | Accepted, no prompt | No |
| Legacy (OmaID) pairing | Accepted with its auth token (plain HTTP) | No; only on explicit `--sync-clipboard` |
| Anyone else | Refused | No |

Text that looks like a credential (private keys, tokens, passwords) is never sent automatically
and is refused on receive.

`GET /api/p2p/clipboard/image?hash=<sha256>` (fetch of an announced clipboard image) requires the
same authorization as `POST /api/p2p/clipboard`: a v2 signature from a paired key (body tag
`hex(SHA-256(""))`), or `X-OmaSend-OmaID` + `X-OmaSend-Auth-Token` of a confirmed legacy
pairing.

### Local control

Decisions on incoming transfers (`POST /api/p2p/decision`), `/api/local/core-send` and
`GET /api/p2p/peers` are for the local user only. They require the `X-OmaSend-Local` header with
the 0600 token in `~/.local/state/omarchy/omasend/local_api.token` on a loopback connection
without proxy headers (a PIN-authenticated web portal session may also decide transfers and list
peers). Loopback alone is not trusted: the WAN tunnel connects from `127.0.0.1`.

## Known limits of the signed-HTTP path

- Traffic is authenticated but **not encrypted**. QR-paired devices use the Phase 2 transport below instead.
- Upload bodies are not covered by the signature (`stream:<len>`). Integrity comes from the
  signed transfer request: the size must match, and hashes are checked when the sender provides them.

## Phase 2: encrypted transport (`omasend-core`)

Paired devices talk over [iroh](https://iroh.computer) (QUIC + TLS 1.3, raw public keys). The
shared Rust crate `core/` is used by the desktop engine directly and by Android through UniFFI
(`core/build-android.sh`).

- **Identity:** the iroh endpoint secret is the same Ed25519 seed as above, so the endpoint id is
  the device `pk`. A connection can only be established to the key stored at pairing time; TLS
  proves the remote holds that key. No certificates, no CA.
- **Transport:** UDP port `53318` (`quic_port` is exchanged during pairing). LAN-only by default:
  relays and discovery are disabled; addresses come from the trust store (last verified IP).
- **ALPN:** `omasend/2`.
- **Control stream** (one bidirectional stream): length-prefixed (u32 BE) JSON frames tagged
  by `t`: `hello` → `offer{transfer_id, files[{name,size,blake3}]}` →
  `decision{accepted, resume[], reason}` → per file `file_done{index, ok, error}` from the
  receiver; or `clipboard{text}` → `ack{ok, error}`.
- **Data:** one unidirectional stream per file, starting with a
  `file_header{transfer_id, index, offset}` frame (offset = the receiver's `resume[index]`),
  followed by the raw bytes. The receiver writes to
  `.omasend-partial/<blake3>.part`, verifies the BLAKE3 hash, then moves it into place.
  A later offer of the same file resumes from the partial length; a hash mismatch deletes the
  partial and fails the transfer (`integrity`).
- **Receiver policy:** trust `Unknown` → refused (files and clipboard); `Paired` → transfers need
  user approval, clipboard accepted; `Own` → transfers auto-accepted, clipboard accepted. File
  names are sanitized (no paths, no leading dots, ≤200 chars).
- **Transfer ids:** the receiver does not use the sender's `transfer_id` for anything but
  matching frames; approvals and cancellation use an id generated by the receiver.
- **Partials:** `.part` files untouched for 7 days are deleted when the node starts. The
  free-space check subtracts data already present in partials.
- **No fallback for paired keys:** a QR-paired device is only ever reached over QUIC. If it is not
  reachable (older version, blocked UDP), the send fails with a firewall hint; it is **not**
  retried over plain HTTP, so blocking UDP cannot downgrade the transport. The signed-HTTP path
  above is for requests *to* this desktop from apps that do not speak QUIC yet.

## Linking with an OmaID (`omasend-link-v1`)

QR pairing needs both devices in hand. Linking lets a user add their *own* devices by typing
one number, the way a Mullvad account number works, without that number ever being
attackable offline.

**Two numbers.** Every install now has:

- the legacy `oma_id`: still carried in beacons and v1 requests, a public label only;
- a secret **account OmaID** (`account_id` on desktop, mode 0600; Keystore-encrypted on
  Android). Same format (16 digits, Luhn), generated randomly, **never sent anywhere**.
  The user reads it in Settings and types it on another device.

**Exchange.** The device where the user typed the number (initiator, I) runs SPAKE2 over
P-256 against every nearby device whose beacon has a `pk` and is not trusted yet. Only a
responder (R) holding the same account OmaID can complete it.

- Points are SEC1 **compressed** (33 bytes); scalars are 32-byte big-endian.
- `M`, `N`: for `seed` = `"omasend-link-v1 M"` / `"omasend-link-v1 N"`, the first
  `ctr = 0, 1, …` for which `0x02 || SHA-256(seed || be32(ctr))` decodes to a curve point.
- `w = SHA-256("omasend-link-v1|w|" || digits) mod n`, where `digits` is the 16 digits
  without separators.
- I: random `x`, `pA = x·G + w·M`. R: random `y`, `pB = y·G + w·N`.
  `K = x·(pB − w·N) = y·(pA − w·M)`; the identity point is rejected everywhere.
- `TT` = for each of `"omasend-link-v1"`, `pA`, `pB`, `K`, `w`: `le64(len) || bytes`.
  `SHA-256(TT)` = `Ke` (first 16 bytes) `|| Ka` (last 16).
- `KcA = HMAC(Ka, "omasend-link-v1 KcA")`, `KcB = HMAC(Ka, "omasend-link-v1 KcB")`,
  `cA = HMAC(KcA, pA || pB)`, `cB = HMAC(KcB, pB || pA)`,
  `box_key = HMAC(Ke, "omasend-link-v1 box")` (all HMAC-SHA256).
- A **box** is `b64url(iv[12] || AES-256-GCM(box_key, iv, json, aad))` with
  `aad = "omasend-link-v1 I"` (I → R) or `"omasend-link-v1 R"` (R → I).

**HTTP** (plain JSON on the existing HTTP port; all binary fields `b64url`):

1. `POST /api/v2/link/start {v:1, pA}` → `{sid, pB, cB}`.
2. I checks `cB`. If it does not match, this device is on another account: I stops and
   sends nothing more.
3. `POST /api/v2/link/finish {sid, cA, box}`; I's box is
   `{pk, name, quic_port, sig}` with `sig` = Ed25519 over `omasend-link-v1|pA|pB|I_pk`
   (the b64url strings joined with `|`).
4. R checks `cA`, opens the box, verifies `sig`, stores I as an **own** device and returns
   `{box}`: `{pk, name, device_id, quic_port, sig}`, `sig` over
   `omasend-link-v1|pA|pB|I_pk|R_pk`. I verifies it and stores R as own.
5. On any success I adopts the typed number as its own account OmaID, so the next device
   can link to either.

**Responder limits.** Refused from loopback (the WAN tunnel) and while visibility is OFF.
Every `start` is one online guess and is counted before any work: at most 5 per source IP
and 20 in total per sliding 10 minutes, at most 32 open sessions. A session lives 30 s, is
bound to the source IP and is consumed by its first `finish`. A successful `finish` gives
its attempt back, so normal use never hits the limit. With 10^15 numbers and at most
20 guesses per 10 minutes, finding a number online takes hundreds of millions of years.

**Changing the number** (`--new-account-id`, "New number" on Android) affects future links
only; devices already linked stay trusted until removed.

### Own-device roster and removal

Linked devices keep each other's list in step, so linking with any one of them joins you to
all of them, and removing a device on one removes it everywhere.

- `POST /api/v2/account/sync` with a **signed** v2 request (see "Signed requests") from a key
  stored as an own device. Anything else is refused (401/403); loopback is refused.
- Body: `{v:1, devices:[{pk, name, ip?, port, quic_port}], revoked:[pk]}`. `devices` holds the
  sender itself plus its own devices (at most 64), `revoked` the removed keys (at most 256).
- The receiver first applies `revoked`: each new key goes on its local revocation list and is
  dropped from the trust store. If any key was new, the receiver also **replaces its account
  OmaID** with a fresh random one, since the removed device knows the old number. If its own
  key is on the list, it was removed: it forgets every own device and stops there.
- Then every listed device that is not itself and not revoked is stored as an own device. The
  sender's address is taken from the connection.
- A device pushes its roster after a link (both sides), after removing an own device, and when
  the engine or app starts. Pushes are best effort; a device that was off catches up on the next
  push it receives.
- Revoked keys can never link again (`/link/finish` and the initiator both refuse them).

After a removal the remaining devices hold different account numbers. Each still works for
linking a new device, and the roster then adds the new device to the rest.

The roster carries no secrets: public keys, names and addresses, on the LAN.

**Not covered yet:** WAN discovery still derives its topic from the legacy `oma_id`. Neither
platform publishes those records anywhere today (desktop anchors are local files, the Android
announcer has no caller), so nothing is exposed; the topic must move to a random account key
before WAN discovery ships. The web client (`omasend-web`) is still v1 and cannot link.

Desktop CLI: `--account-id [--json]`, `--new-account-id`, `--link <OmaID> [--json]`, and
`--unpair <device-id>`, which removes an own device everywhere as above.

## Test vector (must match on both platforms)

| Input | Value |
|---|---|
| seed | 32 bytes of `0x07` |
| pk | `6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw` |
| device_id | `FE81-2C12-F3AB-4CE6` |
| canonical | `POST`, `/api/p2p/request`, ts `1760000000`, nonce `00112233445566778899aabbccddeeff`, body `{}` |
| body_tag | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` |
| sig | `eFkLAbIm3RpexYvL_-DJ6IlojDwGoLd42QJ72_kyhpn7QA_GBOcYOOLoQPw7kI2GeNO0Bl0PZG60gJZvzI9oAA` |
| mac | secret 32×`0x09`, R_pk = I_pk = pk → `58c09b0af9427c54894465e53a59c22480cb28449242df537932d4c659cd1fb7` |

### `omasend-link-v1`

Account OmaID `4539-1488-0343-6467`, `x = 7`, `y = 11` (all hex):

| Value | |
|---|---|
| M | `02bf776f8c956317d2da49785228d6fd711af8a8ee32cb7aba70fd55925d94598e` |
| N | `02eecd84e595f27077112ab183f037c87e132d36742eca41580dbfa80114b12f07` |
| w | `8e139c2abae6f62f14b23470a7bc2e504ab4c23e00bc9e1361044ca4554d7a06` |
| pA | `0230f5731715331f68be2bc69c91e0e3af2c416f559a571bcb6b9faa149e02cf1b` |
| pB | `03ee51e9a4fcceb1b5a8900b4877dc7fc6d13bf10c9451c2e15a2eac27a39e9d18` |
| cA | `b2977414cbce7c32aff0226f3a19c90d80e5e5b778b461f69e60242dbdcf56b0` |
| cB | `0f52e972837c60c635948d111d5b2161d7119281d537c8bc89e6c36efdd01a44` |
| box_key | `f28b858430952bdbde5c49716c49a9df60d6346e57bd7f042d2710ae5eb9b026` |
