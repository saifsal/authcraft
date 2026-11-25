//! OpenID Connect ID token minting and `at_hash` (ADR 0006).

use ring::digest::{self, SHA256};

use jose::alg::Alg;
use jose::b64url;
use jose::jwk::PublicKey;
use jose::signing::{self, SigningError};

use crate::error::OAuthError;
use crate::token::json_escape;

/// Claims for a compact ID token (`typ` = `JWT`).
#[derive(Debug, Clone)]
pub struct IdTokenClaims<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub aud: &'a str,
    pub nonce: &'a str,
    pub at_hash: &'a str,
    pub iat: i64,
    pub exp: i64,
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
    /// OIDC `email_verified`, emitted with `email` when known (ADR 0024).
    pub email_verified: Option<bool>,
}

/// OIDC Core §3.1.3.6 `at_hash` for EdDSA (SHA-256, left 128 bits, base64url).
pub fn at_hash_eddsa(access_token: &str) -> String {
    let digest = digest::digest(&SHA256, access_token.as_bytes());
    let half = &digest.as_ref()[..16];
    b64url::encode(half)
}

/// Signs a compact ID token with EdDSA.
pub fn mint_id_token(
    pkcs8: &[u8],
    public: &PublicKey,
    claims: &IdTokenClaims<'_>,
) -> Result<String, OAuthError> {
    let kid = public.thumbprint();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"JWT"}}"#);
    let mut payload = format!(
        r#"{{"iss":"{}","sub":"{}","aud":"{}","nonce":"{}","at_hash":"{}","iat":{},"exp":{}"#,
        json_escape(claims.iss),
        json_escape(claims.sub),
        json_escape(claims.aud),
        json_escape(claims.nonce),
        json_escape(claims.at_hash),
        claims.iat,
        claims.exp,
    );
    if let Some(name) = claims.name {
        payload.push_str(&format!(r#","name":"{}""#, json_escape(name)));
    }
    if let Some(email) = claims.email {
        payload.push_str(&format!(r#","email":"{}""#, json_escape(email)));
        if let Some(v) = claims.email_verified {
            payload.push_str(&format!(r#","email_verified":{v}"#));
        }
    }
    payload.push('}');

    signing::sign_compact(Alg::EdDSA, pkcs8, header.as_bytes(), payload.as_bytes()).map_err(
        |e| match e {
            SigningError::UnsupportedAlgorithm
            | SigningError::InvalidKey
            | SigningError::KeyGenerationFailed
            | SigningError::SigningFailed
            | SigningError::InvalidProtectedHeader
            | SigningError::AlgorithmMismatch
            | SigningError::UnsupportedCriticalHeader
            | SigningError::InvalidPayload => OAuthError::ServerError,
        },
    )
}

/// True when `scope` contains the space-delimited token `openid`.
pub fn scope_has_openid(scope: Option<&str>) -> bool {
    scope
        .map(|s| s.split_whitespace().any(|t| t == "openid"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openid_scope_detection() {
        assert!(scope_has_openid(Some("openid")));
        assert!(scope_has_openid(Some("openid profile")));
        assert!(scope_has_openid(Some("read openid")));
        assert!(!scope_has_openid(Some("read")));
        assert!(!scope_has_openid(None));
        assert!(!scope_has_openid(Some("openidentity")));
    }

    #[test]
    fn at_hash_is_22_char_base64url() {
        let h = at_hash_eddsa("access.token.value");
        assert_eq!(h.len(), 22);
        assert!(!h.contains('='));
    }
}
