//! `private_key_jwt` client authentication (RFC 7523 §2.2, OIDC Core §9, ADR 0014).
//!
//! The client signs a short-lived JWT with a key from the JWKS it registered.
//! The assertion is verified with the shared `jose` verifier (ADR 0003 check
//! order), then the RFC 7523 claim rules below are applied:
//!
//! - `iss` and `sub` both equal the `client_id`.
//! - `aud` contains the AS issuer identifier. Only the issuer is accepted, not
//!   the token endpoint URL, following the audience-injection fix in
//!   draft-ietf-oauth-rfc7523bis.
//! - `exp` is required and at most [`CLIENT_ASSERTION_MAX_LIFETIME_SECS`] ahead.
//! - `jti` is required and single-use until `exp`.
//!
//! Every failure is `invalid_client`.

use std::collections::HashMap;

use jose::alg::Alg;
use jose::json::Value;
use jose::jwks::Jwks;
use jose::verify::{self, Policy};

use crate::error::OAuthError;

/// RFC 7523 §2.2 `client_assertion_type` value.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Largest accepted `exp - now` for a client assertion (seconds).
pub const CLIENT_ASSERTION_MAX_LIFETIME_SECS: i64 = 300;

/// Largest accepted compact assertion (bytes).
pub const CLIENT_ASSERTION_MAX_BYTES: usize = 8192;

/// Signature algorithms accepted for client assertions. HS256
/// (`client_secret_jwt`) is not supported.
pub const CLIENT_ASSERTION_ALGS: [Alg; 2] = [Alg::EdDSA, Alg::ES256];

/// Remembers assertion `jti` values per client until the assertion expires.
#[derive(Debug, Default)]
pub struct ClientAssertionJtiCache {
    /// (client_id, jti) → expires_at
    seen: HashMap<(String, String), i64>,
}

impl ClientAssertionJtiCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `jti` for `client_id`. A value still remembered is a replay.
    pub fn check_and_store(
        &mut self,
        client_id: &str,
        jti: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<(), OAuthError> {
        self.seen.retain(|_, exp| *exp >= now);
        let key = (client_id.to_owned(), jti.to_owned());
        if self.seen.contains_key(&key) {
            return Err(OAuthError::InvalidClient);
        }
        self.seen.insert(key, expires_at);
        Ok(())
    }
}

/// Parses a registered client JWKS. It must be valid and hold at least one key.
pub fn parse_client_jwks(jwks_json: &str) -> Result<Jwks, OAuthError> {
    let jwks = Jwks::parse(jwks_json.as_bytes()).map_err(|_| OAuthError::InvalidRequest)?;
    if jwks.is_empty() {
        return Err(OAuthError::InvalidRequest);
    }
    Ok(jwks)
}

/// Verifies a `private_key_jwt` assertion for `client_id`.
///
/// `issuer` is the AS issuer identifier and the only accepted audience.
pub fn verify_client_assertion(
    assertion: &str,
    client_id: &str,
    client_jwks: &str,
    issuer: &str,
    now: i64,
    cache: &mut ClientAssertionJtiCache,
) -> Result<(), OAuthError> {
    let jwks = Jwks::parse(client_jwks.as_bytes()).map_err(|_| OAuthError::InvalidClient)?;
    let verified = verify::verify(
        assertion.as_bytes(),
        &jwks,
        &Policy {
            algorithms: CLIENT_ASSERTION_ALGS.to_vec(),
            issuer: Some(client_id.to_owned()),
            audience: Some(issuer.to_owned()),
            now,
            leeway: 0,
            typ: None,
            max_token_bytes: CLIENT_ASSERTION_MAX_BYTES,
        },
    )
    .map_err(|_| OAuthError::InvalidClient)?;

    let claims = &verified.claims;
    if claims.get("sub").and_then(Value::as_str) != Some(client_id) {
        return Err(OAuthError::InvalidClient);
    }
    // `verify` already required an integer `exp` later than `now`.
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(OAuthError::InvalidClient)?;
    if exp.saturating_sub(now) > CLIENT_ASSERTION_MAX_LIFETIME_SECS {
        return Err(OAuthError::InvalidClient);
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or(OAuthError::InvalidClient)?;
    cache.check_and_store(client_id, jti, exp, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::signing::{generate_signing_key, sign_compact, SigningKey};

    const AS: &str = "https://auth.example";

    fn jwks_for(key: &SigningKey) -> (String, String) {
        let kid = key.public.thumbprint();
        let canonical = key.public.canonical_json();
        // canonical_json is `{...}`; splice in `kid`.
        let jwk = format!(r#"{{"kid":"{kid}",{}"#, &canonical[1..]);
        (format!(r#"{{"keys":[{jwk}]}}"#), kid)
    }

    fn assertion(key: &SigningKey, kid: &str, claims: &str) -> String {
        let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#);
        sign_compact(Alg::EdDSA, &key.pkcs8, header.as_bytes(), claims.as_bytes()).unwrap()
    }

    fn claims(iss: &str, sub: &str, aud: &str, jti: &str, exp: i64) -> String {
        format!(r#"{{"iss":"{iss}","sub":"{sub}","aud":"{aud}","jti":"{jti}","exp":{exp}}}"#)
    }

    fn setup() -> (SigningKey, String, String) {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let (jwks, kid) = jwks_for(&key);
        (key, jwks, kid)
    }

    #[test]
    fn accepts_valid_assertion_once() {
        let (key, jwks, kid) = setup();
        let a = assertion(&key, &kid, &claims("svc", "svc", AS, "j1", 1_060));
        let mut cache = ClientAssertionJtiCache::new();
        assert_eq!(
            verify_client_assertion(&a, "svc", &jwks, AS, 1_000, &mut cache),
            Ok(())
        );
        assert_eq!(
            verify_client_assertion(&a, "svc", &jwks, AS, 1_001, &mut cache),
            Err(OAuthError::InvalidClient)
        );
    }

    #[test]
    fn rejects_wrong_claims() {
        let (key, jwks, kid) = setup();
        let cases = [
            claims("other", "svc", AS, "a", 1_060),
            claims("svc", "other", AS, "b", 1_060),
            claims("svc", "svc", "https://auth.example/token", "c", 1_060),
            claims("svc", "svc", AS, "", 1_060),
            claims("svc", "svc", AS, "e", 999),
            claims("svc", "svc", AS, "f", 1_000 + CLIENT_ASSERTION_MAX_LIFETIME_SECS + 1),
            format!(r#"{{"iss":"svc","sub":"svc","aud":"{AS}","exp":1060}}"#),
        ];
        for c in cases {
            let a = assertion(&key, &kid, &c);
            let mut cache = ClientAssertionJtiCache::new();
            assert_eq!(
                verify_client_assertion(&a, "svc", &jwks, AS, 1_000, &mut cache),
                Err(OAuthError::InvalidClient),
                "{c}"
            );
        }
    }

    #[test]
    fn accepts_audience_array_containing_issuer() {
        let (key, jwks, kid) = setup();
        let c = format!(
            r#"{{"iss":"svc","sub":"svc","aud":["x","{AS}"],"jti":"j","exp":1060}}"#
        );
        let a = assertion(&key, &kid, &c);
        let mut cache = ClientAssertionJtiCache::new();
        assert!(verify_client_assertion(&a, "svc", &jwks, AS, 1_000, &mut cache).is_ok());
    }

    #[test]
    fn rejects_key_not_in_registered_jwks() {
        let (_, jwks, kid) = setup();
        let attacker = generate_signing_key(Alg::EdDSA).unwrap();
        let a = assertion(&attacker, &kid, &claims("svc", "svc", AS, "j", 1_060));
        let mut cache = ClientAssertionJtiCache::new();
        assert_eq!(
            verify_client_assertion(&a, "svc", &jwks, AS, 1_000, &mut cache),
            Err(OAuthError::InvalidClient)
        );
    }

    #[test]
    fn jti_scope_is_per_client_and_expires() {
        let mut cache = ClientAssertionJtiCache::new();
        assert!(cache.check_and_store("a", "j", 1_010, 1_000).is_ok());
        assert!(cache.check_and_store("b", "j", 1_010, 1_000).is_ok());
        assert!(cache.check_and_store("a", "j", 1_020, 1_005).is_err());
        assert!(cache.check_and_store("a", "j", 1_020, 1_011).is_ok());
    }

    #[test]
    fn client_jwks_must_be_non_empty() {
        assert!(parse_client_jwks(r#"{"keys":[]}"#).is_err());
        assert!(parse_client_jwks("nope").is_err());
        let (_, jwks, _) = setup();
        assert!(parse_client_jwks(&jwks).is_ok());
    }
}
