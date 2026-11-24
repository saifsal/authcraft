//! OAuth 2.0 mutual-TLS helpers (RFC 8705, ADR 0017).
//!
//! The library is transport-agnostic: the HTTP layer terminates TLS and passes
//! the DER bytes of the client's leaf certificate. This module computes the
//! RFC 8705 §3.1 `x5t#S256` thumbprint and reads the certificates a
//! `self_signed_tls_client_auth` client registers as `x5c` in its JWKS
//! (RFC 8705 §2.2.2). Certificates are compared byte-for-byte by thumbprint;
//! no X.509 parsing or chain validation happens here.

use jose::b64url;
use jose::json::{self, Value};
use ring::digest;

use crate::error::OAuthError;

/// RFC 8705 §3.1 `x5t#S256`: base64url(SHA-256(DER certificate)).
pub fn cert_thumbprint(der: &[u8]) -> String {
    b64url::encode(digest::digest(&digest::SHA256, der).as_ref())
}

/// Decodes standard (RFC 4648 §4) base64, as used by JWK `x5c`.
///
/// Translates to the base64url alphabet and reuses the strict canonical
/// decoder, so padding must be correct and unused bits must be zero.
fn decode_std_base64(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.strip_suffix("==").or_else(|| s.strip_suffix('=')).unwrap_or(s);
    if trimmed.contains('=') || trimmed.contains('-') || trimmed.contains('_') {
        return None;
    }
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let url: String = trimmed
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    b64url::decode(&url).ok()
}

/// Thumbprints of the first `x5c` certificate of every key in a JWKS
/// document. Every key must carry a non-empty `x5c` array of base64 DER
/// strings, and there must be at least one key.
pub fn thumbprints_from_jwks(jwks_json: &str) -> Result<Vec<String>, OAuthError> {
    let doc = json::parse(jwks_json.as_bytes()).map_err(|_| OAuthError::InvalidRequest)?;
    let Some(Value::Array(keys)) = doc.get("keys") else {
        return Err(OAuthError::InvalidRequest);
    };
    if keys.is_empty() {
        return Err(OAuthError::InvalidRequest);
    }
    keys.iter()
        .map(|key| {
            let Some(Value::Array(chain)) = key.get("x5c") else {
                return Err(OAuthError::InvalidRequest);
            };
            let leaf = chain
                .first()
                .and_then(Value::as_str)
                .ok_or(OAuthError::InvalidRequest)?;
            let der = decode_std_base64(leaf).ok_or(OAuthError::InvalidRequest)?;
            if der.is_empty() {
                return Err(OAuthError::InvalidRequest);
            }
            Ok(cert_thumbprint(&der))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_is_sha256_b64url() {
        // SHA-256("abc"), FIPS 180-2 B.1.
        assert_eq!(
            cert_thumbprint(b"abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn std_base64_decoding() {
        assert_eq!(decode_std_base64("YWJj").unwrap(), b"abc");
        assert_eq!(decode_std_base64("YWI=").unwrap(), b"ab");
        assert_eq!(decode_std_base64("YQ==").unwrap(), b"a");
        assert_eq!(decode_std_base64("+/8=").unwrap(), [0xfb, 0xff]);
        for bad in ["YWI", "YQ=", "Y===", "-_8=", "YW=j", "YR=="] {
            assert!(decode_std_base64(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn jwks_thumbprints() {
        let ok = r#"{"keys":[{"kty":"OKP","x5c":["YWJj","ignored"]},{"x5c":["YWI="]}]}"#;
        assert_eq!(
            thumbprints_from_jwks(ok).unwrap(),
            vec![cert_thumbprint(b"abc"), cert_thumbprint(b"ab")]
        );
        for bad in [
            r#"{"keys":[]}"#,
            r#"{"keys":[{"kty":"OKP"}]}"#,
            r#"{"keys":[{"x5c":[]}]}"#,
            r#"{"keys":[{"x5c":[7]}]}"#,
            r#"{"keys":[{"x5c":["not base64!"]}]}"#,
            "nope",
        ] {
            assert_eq!(thumbprints_from_jwks(bad), Err(OAuthError::InvalidRequest), "{bad}");
        }
    }
}
