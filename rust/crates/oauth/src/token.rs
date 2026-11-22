//! Access-token minting via the jose signer (ADR 0005).

use jose::alg::Alg;
use jose::jwk::PublicKey;
use jose::signing::{self, SigningError};

use crate::error::OAuthError;

/// Default access-token lifetime in seconds.
pub const DEFAULT_ACCESS_TOKEN_TTL_SECS: i64 = 300;

#[derive(Debug, Clone)]
pub struct TokenClaims<'a> {
    pub iss: &'a str,
    pub aud: &'a str,
    pub sub: &'a str,
    pub client_id: &'a str,
    pub jti: &'a str,
    pub scope: Option<&'a str>,
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub iat: i64,
    pub exp: i64,
}

/// Signs a compact `at+jwt` access token with EdDSA.
pub fn mint_access_token(
    pkcs8: &[u8],
    public: &PublicKey,
    claims: &TokenClaims<'_>,
) -> Result<String, OAuthError> {
    let kid = public.thumbprint();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"at+jwt"}}"#);
    let mut payload = format!(
        r#"{{"iss":"{}","aud":"{}","sub":"{}","client_id":"{}","jti":"{}","iat":{},"exp":{}"#,
        json_escape(claims.iss),
        json_escape(claims.aud),
        json_escape(claims.sub),
        json_escape(claims.client_id),
        json_escape(claims.jti),
        claims.iat,
        claims.exp,
    );
    if let Some(scope) = claims.scope {
        payload.push_str(&format!(r#","scope":"{}""#, json_escape(scope)));
    }
    if let Some(name) = claims.name {
        payload.push_str(&format!(r#","name":"{}""#, json_escape(name)));
    }
    if let Some(email) = claims.email {
        payload.push_str(&format!(r#","email":"{}""#, json_escape(email)));
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

pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
