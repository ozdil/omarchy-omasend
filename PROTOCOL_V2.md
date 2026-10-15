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
omasend://pair?v=2&pk=<b64url R_pk>&s=<b64url 32-byte secret>&h=<ip>&p=<port>&n=<urlenc name>&o=<0|1>
```

`o=1` means "the new device will be trusted as one of my own devices". That trust level
enables auto-accept of transfers.

The **initiator** scans the QR code and sends:

```
POST /api/v2/pair
{ "pk":   b64url(I_pk),
  "name": "<initiator name>",
  "mac":  hex(HMAC-SHA256(secret, "omasend-pair-v2|" + R_pk + "|" + I_pk)),
  "sig":  b64url(Ed25519_I("omasend-pair-v2|" + R_pk + "|" + I_pk + "|" + mac)) }
```

The responder checks:

1. An unexpired offer exists whose secret produces the same `mac`.
2. `sig` verifies with `I_pk`.

If both pass, it consumes the offer, stores `I_pk`, and replies:

```
200 { "pk": b64url(R_pk), "name": "...", "device_id": "...",
      "sig": b64url(Ed25519_R(same transcript)) }
```

The initiator checks that `pk` equals the key from the QR code, then verifies `sig`.

Protection against guessing: after 5 failed attempts, every open offer is burned.

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
handles DHCP address changes without trusting unauthenticated beacons.

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
- **Receiver policy:** trust `Unknown` → refused (files and clipboard); `Paired` → user approval;
  `Own` → auto-accept. File names are sanitized (no paths, no leading dots, ≤200 chars).
- **Fallback:** if the peer has no reachable QUIC endpoint (older version, blocked UDP), senders
  fall back to the signed-HTTP path above.

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
