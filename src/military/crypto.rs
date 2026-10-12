use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protected sensitive byte sequence in RAM. Automatically wiped with zeroes when dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ProtectedBytes {
    inner: Vec<u8>,
}

impl ProtectedBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Protected PIN or session secret in RAM. Automatically wiped on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ProtectedSecret {
    secret: String,
}

impl ProtectedSecret {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    pub fn as_str(&self) -> &str {
        &self.secret
    }
}

/// Military-grade cryptographic checksum bundle incorporating Post-Quantum Tree Hash (BLAKE3),
/// NIST FIPS-180-4 standard (SHA-256), and legacy interoperability hash (MD5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MilitaryChecksums {
    pub blake3_hex: String,
    pub sha256_hex: String,
    pub md5_hex: String,
}

/// Computes BLAKE3, SHA-256, and MD5 simultaneously in a single stream pass.
pub fn compute_stream_checksums<R: Read>(mut reader: R) -> io::Result<MilitaryChecksums> {
    let mut blake3_hasher = blake3::Hasher::new();
    let mut sha256_hasher = Sha256::new();
    let mut md5_context = md5::Context::new();

    let mut buffer = [0u8; 64 * 1024]; // 64 KiB chunk for cache locality and speed
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let chunk = &buffer[..bytes_read];
        blake3_hasher.update(chunk);
        sha256_hasher.update(chunk);
        md5_context.consume(chunk);
    }

    // Zero out stack buffer after calculation
    buffer.zeroize();

    let blake3_hex = blake3_hasher.finalize().to_hex().to_string();
    let sha256_hex = hex::encode(sha256_hasher.finalize());
    let md5_hex = hex::encode(md5_context.compute().0);

    Ok(MilitaryChecksums {
        blake3_hex,
        sha256_hex,
        md5_hex,
    })
}

/// Computes military checksums directly from a file path.
pub fn compute_file_military_checksums<P: AsRef<Path>>(path: P) -> io::Result<MilitaryChecksums> {
    let file = File::open(path)?;
    compute_stream_checksums(file)
}

/// Verifies file integrity against military standards.
/// BLAKE3 or SHA-256 must match if provided.
/// If both BLAKE3 and SHA-256 are provided, both must match.
pub fn verify_file_military_integrity<P: AsRef<Path>>(
    path: P,
    expected_blake3: Option<&str>,
    expected_sha256: Option<&str>,
    expected_md5: Option<&str>,
) -> io::Result<bool> {
    let actual = compute_file_military_checksums(path)?;

    if let Some(exp_b3) = expected_blake3 {
        if !exp_b3.is_empty() && !exp_b3.eq_ignore_ascii_case(&actual.blake3_hex) {
            return Ok(false);
        }
    }

    if let Some(exp_sha) = expected_sha256 {
        if !exp_sha.is_empty() && !exp_sha.eq_ignore_ascii_case(&actual.sha256_hex) {
            return Ok(false);
        }
    }

    if let Some(exp_md5) = expected_md5 {
        if !exp_md5.is_empty() && !exp_md5.eq_ignore_ascii_case(&actual.md5_hex) {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Sensitive Clipboard Shield: Heuristics to detect passwords, private keys,
/// tokens, recovery phrases, and sensitive clipboard data to prevent accidental leak.
pub fn is_sensitive_clipboard_payload(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }

    // 1. Private keys, certificates and secrets
    if t.contains("BEGIN PRIVATE KEY")
        || t.contains("BEGIN RSA PRIVATE KEY")
        || t.contains("BEGIN OPENSSH PRIVATE KEY")
        || t.contains("BEGIN PGP PRIVATE KEY")
        || t.contains("BEGIN CERTIFICATE")
    {
        return true;
    }

    // 2. High-entropy API tokens and cloud secrets
    if t.starts_with("ghp_") || t.starts_with("gho_") || t.starts_with("ghu_") || t.starts_with("ghs_") // GitHub
        || t.starts_with("glpat-") // GitLab
        || t.starts_with("sk_live_") || t.starts_with("rk_live_") // Stripe
        || t.starts_with("AIzaSy") // Google API key
        || t.starts_with("AKIA") || t.starts_with("ASIA") // AWS Access Key
        || t.starts_with("xoxb-") || t.starts_with("xoxp-") // Slack token
        || (t.starts_with("eyJ") && t.contains('.') && t.matches('.').count() == 2) // JWT token
    {
        return true;
    }

    // 3. Multi-word BIP-39 mnemonic phrase detection (12 or 24 words with no punctuation)
    let words: Vec<&str> = t.split_whitespace().collect();
    if (words.len() == 12 || words.len() == 24)
        && words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
    {
        return true;
    }

    // 4. Typical high-entropy password/token heuristic (single continuous token, 20-128 chars, mixed casing, digits, specials)
    if !t.contains(' ') && !t.contains('\n') && !t.contains('/') && !t.contains('.') && t.len() >= 20 && t.len() <= 128 {
        let has_upper = t.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = t.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = t.chars().any(|c| c.is_ascii_digit());
        let has_special = t.chars().any(|c| "!@#$%^&*()-_=+[]{}|;:,<>?".contains(c));
        if has_upper && has_lower && has_digit && has_special {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_sensitive_clipboard_shield() {
        // Safe strings
        assert!(!is_sensitive_clipboard_payload("https://github.com/ozdil/omasend"));
        assert!(!is_sensitive_clipboard_payload("Hello world! Check this text."));
        assert!(!is_sensitive_clipboard_payload("192.168.1.100"));

        // Sensitive private keys
        assert!(is_sensitive_clipboard_payload("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ..."));
        assert!(is_sensitive_clipboard_payload("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza..."));

        // Sensitive API tokens
        assert!(is_sensitive_clipboard_payload("ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"));
        assert!(is_sensitive_clipboard_payload("sk_live_51Abcdefghijklmnop"));
        assert!(is_sensitive_clipboard_payload("AKIAIOSFODNN7EXAMPLE"));
        assert!(is_sensitive_clipboard_payload("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozS6-m_sample"));

        // BIP-39 12-word mnemonic phrase
        let mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident";
        assert!(is_sensitive_clipboard_payload(mnemonic));

        // High entropy generated password
        assert!(is_sensitive_clipboard_payload("kX9#mP$2vL@8qR*1zT&4wY!7"));
    }

    #[test]
    fn test_zeroize_memory_protection() {
        let mut secret = ProtectedSecret::new("super_secret_pin_12345".to_string());
        assert_eq!(secret.as_str(), "super_secret_pin_12345");
        // Manual zeroize test
        secret.zeroize();
        assert!(secret.as_str().chars().all(|c| c == '\0'));
    }

    #[test]
    fn test_military_checksum_vectors() {
        let data = b"Omarchy military-grade zero-trust protocol test vector";
        let checksums = compute_stream_checksums(Cursor::new(data)).expect("stream checksums failed");

        let expected_blake3 = blake3::hash(data).to_hex().to_string();
        assert_eq!(checksums.blake3_hex, expected_blake3);

        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected_sha256 = hex::encode(hasher.finalize());
        assert_eq!(checksums.sha256_hex, expected_sha256);

        let expected_md5 = hex::encode(md5::compute(data).0);
        assert_eq!(checksums.md5_hex, expected_md5);
    }

    #[test]
    fn test_integrity_verification_logic() {
        let dir = std::env::temp_dir();
        let test_file = dir.join("military_integrity_test.tmp");
        std::fs::write(&test_file, b"Defend against quantum threats and bit-flipping attacks").unwrap();

        let checksums = compute_file_military_checksums(&test_file).unwrap();

        // Valid match
        assert!(verify_file_military_integrity(
            &test_file,
            Some(&checksums.blake3_hex),
            Some(&checksums.sha256_hex),
            Some(&checksums.md5_hex)
        ).unwrap());

        // Tampered BLAKE3
        assert!(!verify_file_military_integrity(
            &test_file,
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            Some(&checksums.sha256_hex),
            Some(&checksums.md5_hex)
        ).unwrap());

        // Clean up
        let _ = std::fs::remove_file(test_file);
    }
}
