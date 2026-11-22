//! PKCE (RFC 7636) with S256 only (ADR 0005).

use ring::digest::{self, SHA256};

use crate::error::OAuthError;
use jose::b64url;

/// RFC 7636 §4.1: verifier length.
pub const VERIFIER_MIN_LEN: usize = 43;
pub const VERIFIER_MAX_LEN: usize = 128;

fn is_unreserved(b: u8) -> bool {
    matches!(
        b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

/// Validates a `code_verifier` character set and length.
pub fn validate_verifier(verifier: &str) -> Result<(), OAuthError> {
    let len = verifier.len();
    if !(VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&len) {
        return Err(OAuthError::InvalidRequest);
    }
    if !verifier.bytes().all(is_unreserved) {
        return Err(OAuthError::InvalidRequest);
    }
    Ok(())
}

/// Computes `BASE64URL(SHA256(ascii(verifier)))` for S256.
pub fn challenge_s256(verifier: &str) -> Result<String, OAuthError> {
    validate_verifier(verifier)?;
    let digest = digest::digest(&SHA256, verifier.as_bytes());
    Ok(b64url::encode(digest.as_ref()))
}

/// Returns Ok when the verifier matches the stored S256 challenge.
pub fn verify_s256(verifier: &str, challenge: &str) -> Result<(), OAuthError> {
    let computed = challenge_s256(verifier)?;
    if computed != challenge {
        return Err(OAuthError::InvalidGrant);
    }
    Ok(())
}

/// Rejects any method other than `S256` (case-sensitive).
pub fn require_s256_method(method: &str) -> Result<(), OAuthError> {
    if method == "S256" {
        Ok(())
    } else {
        Err(OAuthError::InvalidRequest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_round_trip() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = challenge_s256(verifier).unwrap();
        // RFC 7636 Appendix B
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        verify_s256(verifier, &challenge).unwrap();
    }

    #[test]
    fn rejects_plain_method() {
        assert_eq!(
            require_s256_method("plain"),
            Err(OAuthError::InvalidRequest)
        );
    }

    #[test]
    fn rejects_short_verifier() {
        assert_eq!(
            validate_verifier(&"a".repeat(42)),
            Err(OAuthError::InvalidRequest)
        );
    }

    #[test]
    fn wrong_verifier_is_invalid_grant() {
        let challenge = challenge_s256(&"a".repeat(43)).unwrap();
        assert_eq!(
            verify_s256(&"b".repeat(43), &challenge),
            Err(OAuthError::InvalidGrant)
        );
    }
}
