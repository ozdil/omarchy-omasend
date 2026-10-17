//! End-to-end encryption for the browser client (`omasend-web`), "omasend-web-e2e-v1".
//!
//! A browser on `http://<lan-ip>` has no QUIC and no secure context, so it keeps using the
//! signed-HTTP endpoints. This layer encrypts what it sends on top of them, so a passive
//! listener on the LAN sees only sizes (PROTOCOL_V2.md, "Browser end-to-end encryption"):
//!
//! - The desktop has a static X25519 key derived from its Ed25519 seed (HKDF, own domain) and
//!   publishes it signed by its Ed25519 key. The browser pinned that Ed25519 key at pairing.
//! - Each request or clipboard message carries a fresh browser X25519 key (`epk`) inside the
//!   signed JSON body, so the desktop knows which paired browser it belongs to.
//! - `K = HKDF(salt = epk || x_pk, ikm = X25519(e, x_pk), info = DOMAIN | browser_pk)`;
//!   every purpose gets its own subkey, used once.
//! - Metadata and clipboard text: one ChaCha20-Poly1305 message. Files: 64 KiB chunks with
//!   a counter nonce and a final-chunk flag, so chunks cannot be reordered, dropped or cut off.
//!
//! Everything here is pure (no sockets, no global state) and covered by the test vector that
//! `omasend-web` checks too.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::io::{Read, Write};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::devicekey::DeviceIdentity;
use crate::rendezvous::hmac_sha256;

pub const DOMAIN: &str = "omasend-web-e2e-v1";
pub const VERSION: u64 = 1;
/// Plaintext bytes per file chunk.
pub const CHUNK: usize = 64 * 1024;
pub const TAG: usize = 16;

pub const LABEL_REQUEST: &str = "request";
pub const LABEL_CLIPBOARD: &str = "clipboard";

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let prk = Zeroizing::new(hmac_sha256(salt, ikm));
    let mut t1 = info.to_vec();
    t1.push(1);
    Zeroizing::new(hmac_sha256(&prk[..], &t1))
}

/// The desktop's static X25519 secret, derived from its device seed with its own domain.
pub fn static_secret(identity: &DeviceIdentity) -> StaticSecret {
    let seed = Zeroizing::new(identity.seed());
    let okm = hkdf_sha256(format!("{} static", DOMAIN).as_bytes(), &seed[..], b"x25519");
    StaticSecret::from(*okm)
}

pub fn static_public_b64(identity: &DeviceIdentity) -> String {
    B64.encode(PublicKey::from(&static_secret(identity)).as_bytes())
}

/// String the desktop signs to vouch for its X25519 key.
pub fn advert_transcript(ed_pk_b64: &str, x_pk_b64: &str) -> String {
    format!("{}|{}|{}", DOMAIN, ed_pk_b64, x_pk_b64)
}

/// `{"v":1,"x25519":..,"sig":..}`, sent with the pair response and by `GET /api/v2/e2e`.
pub fn advert(identity: &DeviceIdentity) -> serde_json::Value {
    let x = static_public_b64(identity);
    let sig = identity.sign_b64(advert_transcript(&identity.public_b64(), &x).as_bytes());
    serde_json::json!({ "v": VERSION, "x25519": x, "sig": sig })
}

/// Per-message key from the browser's ephemeral public key.
pub fn message_key(secret: &StaticSecret, epk_b64: &str, browser_pk_b64: &str) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let epk: [u8; 32] = B64
        .decode(epk_b64.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("Invalid ephemeral key")?;
    let epk = PublicKey::from(epk);
    let shared = secret.diffie_hellman(&epk);
    // A low-order point gives an all-zero secret that an attacker could predict.
    if !shared.was_contributory() {
        return Err("Invalid ephemeral key");
    }
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(epk.as_bytes());
    salt.extend_from_slice(PublicKey::from(secret).as_bytes());
    let info = format!("{}|{}", DOMAIN, browser_pk_b64);
    Ok(hkdf_sha256(&salt, shared.as_bytes(), info.as_bytes()))
}

pub fn subkey(k: &[u8; 32], label: &str) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hmac_sha256(k, format!("{}|{}", DOMAIN, label).as_bytes()))
}

pub fn file_label(index: usize) -> String {
    format!("file|{}", index)
}

/// Opens a one-shot message (metadata or clipboard). The subkey is used for this message only,
/// so a zero nonce is safe.
pub fn open_message(k: &[u8; 32], label: &str, ct: &[u8]) -> Result<Vec<u8>, &'static str> {
    let sk = subkey(k, label);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sk[..]));
    cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: ct, aad: label.as_bytes() })
        .map_err(|_| "Decryption failed")
}

#[cfg(test)]
pub fn seal_message(k: &[u8; 32], label: &str, pt: &[u8]) -> Vec<u8> {
    let sk = subkey(k, label);
    ChaCha20Poly1305::new(Key::from_slice(&sk[..]))
        .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: pt, aad: label.as_bytes() })
        .expect("encrypt")
}

/// Decrypts the `e2e` object of a signed request: `{"v":1,"epk":..,"ct":..}`.
pub fn open_envelope(
    identity: &DeviceIdentity,
    env: &serde_json::Value,
    browser_pk_b64: &str,
    label: &str,
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), &'static str> {
    if env["v"].as_u64() != Some(VERSION) {
        return Err("Unsupported encryption version");
    }
    let epk = env["epk"].as_str().ok_or("Missing ephemeral key")?;
    let ct = env["ct"].as_str().and_then(|c| B64.decode(c).ok()).ok_or("Invalid ciphertext")?;
    let k = message_key(&static_secret(identity), epk, browser_pk_b64)?;
    let pt = open_message(&k, label, &ct)?;
    Ok((k, pt))
}

pub fn chunk_count(plain_size: u64) -> u64 {
    plain_size.div_ceil(CHUNK as u64).max(1)
}

/// Exact length of an encrypted file body.
pub fn ciphertext_len(plain_size: u64) -> u64 {
    plain_size.saturating_add(chunk_count(plain_size).saturating_mul(TAG as u64))
}

fn chunk_nonce(index: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[3] = last as u8;
    n[4..].copy_from_slice(&index.to_be_bytes());
    n
}

/// What the browser does: the message key and `epk` for an ephemeral secret.
#[cfg(test)]
pub fn browser_message_key(x_pk_b64: &str, eph: [u8; 32], browser_pk: &str) -> ([u8; 32], String) {
    let x_pk: [u8; 32] = B64.decode(x_pk_b64).unwrap().try_into().unwrap();
    let e = StaticSecret::from(eph);
    let epk = PublicKey::from(&e);
    let shared = e.diffie_hellman(&PublicKey::from(x_pk));
    let mut salt = epk.as_bytes().to_vec();
    salt.extend_from_slice(&x_pk);
    let k = hkdf_sha256(&salt, shared.as_bytes(), format!("{}|{}", DOMAIN, browser_pk).as_bytes());
    (*k, B64.encode(epk.as_bytes()))
}

#[cfg(test)]
pub fn seal_file(k: &[u8; 32], index: usize, pt: &[u8]) -> Vec<u8> {
    let sk = subkey(k, &file_label(index));
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sk[..]));
    let n = chunk_count(pt.len() as u64);
    let mut out = Vec::new();
    for i in 0..n {
        let start = (i as usize) * CHUNK;
        let end = (start + CHUNK).min(pt.len());
        let ct = cipher.encrypt(Nonce::from_slice(&chunk_nonce(i, i + 1 == n)), &pt[start..end]).expect("encrypt");
        out.extend_from_slice(&ct);
    }
    out
}

/// Streams an encrypted file body from `r` to `w`, checking every chunk in order. Fails on a
/// wrong tag, a short body or trailing bytes. Returns the SHA-256 (hex) of the plaintext.
pub fn decrypt_file<R: Read, W: Write>(k: &[u8; 32], index: usize, plain_size: u64, mut r: R, mut w: W) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let sk = subkey(k, &file_label(index));
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sk[..]));
    let n = chunk_count(plain_size);
    let mut remaining = plain_size;
    let mut buf = vec![0u8; CHUNK + TAG];
    let mut sha = Sha256::new();
    for i in 0..n {
        let plain_len = remaining.min(CHUNK as u64) as usize;
        let ct = &mut buf[..plain_len + TAG];
        r.read_exact(ct).map_err(|_| "Encrypted upload is truncated".to_string())?;
        let pt = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&chunk_nonce(i, i + 1 == n)), &ct[..])
                .map_err(|_| "File integrity verification failed: decryption error".to_string())?,
        );
        sha.update(&pt[..]);
        w.write_all(&pt).map_err(|e| format!("Failed to write file: {}", e))?;
        remaining -= plain_len as u64;
    }
    let mut extra = [0u8; 1];
    if r.read(&mut extra).map_err(|e| e.to_string())? != 0 {
        return Err("Encrypted upload has trailing data".to_string());
    }
    w.flush().map_err(|e| e.to_string())?;
    Ok(hex::encode(sha.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_seed([7u8; 32])
    }

    fn browser_side(x_pk: &[u8; 32], eph: [u8; 32], browser_pk: &str) -> ([u8; 32], String) {
        browser_message_key(&B64.encode(x_pk), eph, browser_pk)
    }

    fn x_pk() -> [u8; 32] {
        B64.decode(static_public_b64(&identity())).unwrap().try_into().unwrap()
    }

    #[test]
    fn test_vector_matches_web_client() {
        // The same values are asserted in omasend-web test/e2e.test.ts.
        let id = identity();
        assert_eq!(static_public_b64(&id), "i4jc1T3UEWi-5t2YzAAjCBEvhgfStTFDplY870idOh4");
        assert_eq!(
            advert(&id)["sig"],
            "oF7kdBK8YQt5QQVY6UupXgnzKHgZKR9t6EcfdA0o1If1aqLP87bB4tsUBQmtJQFRJKN7r9jBcCFrNaqnR9j4Cg"
        );
        let (k, epk) = browser_side(&x_pk(), [9u8; 32], &id.public_b64());
        assert_eq!(epk, "V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE");
        assert_eq!(hex::encode(k), "dbeb88569654dc8de014733f6ce06b98b93b27eb5dbbb11cd01f8eccbc647c52");
        assert_eq!(*message_key(&static_secret(&id), &epk, &id.public_b64()).unwrap(), k);
        assert_eq!(B64.encode(seal_message(&k, LABEL_CLIPBOARD, b"hello")), "F1-YlDras6142gWgkZ74xfy9p8cS");
        assert_eq!(hex::encode(seal_file(&k, 0, b"")), "d1c15f58b133dc819d93998d773bffed");
        assert_eq!(hex::encode(seal_file(&k, 1, b"abc")), "f64a652799246345385f30fcbf232b0a319739");
    }

    #[test]
    fn test_advert_signature_verifies() {
        let id = identity();
        let a = advert(&id);
        let vk = crate::devicekey::decode_pk(&id.public_b64()).unwrap();
        let t = advert_transcript(&id.public_b64(), a["x25519"].as_str().unwrap());
        assert!(crate::devicekey::verify_b64(&vk, t.as_bytes(), a["sig"].as_str().unwrap()));
        assert_eq!(a["v"], 1);
    }

    #[test]
    fn test_envelope_round_trip_and_binding() {
        let id = identity();
        let browser = DeviceIdentity::from_seed([3u8; 32]).public_b64();
        let (k, epk) = browser_side(&x_pk(), [11u8; 32], &browser);
        let ct = seal_message(&k, LABEL_REQUEST, br#"{"files":[]}"#);
        let env = serde_json::json!({ "v": 1, "epk": epk, "ct": B64.encode(&ct) });
        let (k2, pt) = open_envelope(&id, &env, &browser, LABEL_REQUEST).unwrap();
        assert_eq!(pt, br#"{"files":[]}"#);
        assert_eq!(*k2, k);
        // Bound to the signing browser key and to the purpose.
        let other = DeviceIdentity::from_seed([4u8; 32]).public_b64();
        assert!(open_envelope(&id, &env, &other, LABEL_REQUEST).is_err());
        assert!(open_envelope(&id, &env, &browser, LABEL_CLIPBOARD).is_err());
        // Flipped ciphertext bit.
        let mut bad = ct.clone();
        bad[0] ^= 1;
        let env_bad = serde_json::json!({ "v": 1, "epk": epk, "ct": B64.encode(&bad) });
        assert!(open_envelope(&id, &env_bad, &browser, LABEL_REQUEST).is_err());
        // Wrong version, low-order point.
        let env_v2 = serde_json::json!({ "v": 2, "epk": epk, "ct": B64.encode(&ct) });
        assert!(open_envelope(&id, &env_v2, &browser, LABEL_REQUEST).is_err());
        let zero = serde_json::json!({ "v": 1, "epk": B64.encode([0u8; 32]), "ct": B64.encode(&ct) });
        assert_eq!(open_envelope(&id, &zero, &browser, LABEL_REQUEST).unwrap_err(), "Invalid ephemeral key");
    }

    #[test]
    fn test_file_stream_round_trip_and_tampering() {
        let k = [5u8; 32];
        for size in [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            let pt: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            let ct = seal_file(&k, 2, &pt);
            assert_eq!(ct.len() as u64, ciphertext_len(size as u64), "size {}", size);
            let mut out = Vec::new();
            let sha = decrypt_file(&k, 2, size as u64, &ct[..], &mut out).unwrap();
            assert_eq!(out, pt);
            use sha2::{Digest, Sha256};
            assert_eq!(sha, hex::encode(Sha256::digest(&pt)));
            // Other file index (other subkey).
            assert!(decrypt_file(&k, 3, size as u64, &ct[..], &mut Vec::new()).is_err());
            // Truncated, extended.
            assert!(decrypt_file(&k, 2, size as u64, &ct[..ct.len() - 1], &mut Vec::new()).is_err());
            let mut longer = ct.clone();
            longer.push(0);
            assert!(decrypt_file(&k, 2, size as u64, &longer[..], &mut Vec::new()).is_err());
        }
        // Dropping the final chunk: the new last chunk was not sealed as final.
        let pt = vec![1u8; 2 * CHUNK];
        let ct = seal_file(&k, 0, &pt);
        let cut = &ct[..CHUNK + TAG];
        assert!(decrypt_file(&k, 0, CHUNK as u64, cut, &mut Vec::new()).is_err());
        // Swapping two chunks.
        let mut swapped = ct[CHUNK + TAG..].to_vec();
        swapped.extend_from_slice(&ct[..CHUNK + TAG]);
        assert!(decrypt_file(&k, 0, pt.len() as u64, &swapped[..], &mut Vec::new()).is_err());
    }
}
