//! JWT-secured authorization requests (RFC 9101 JAR, ADR 0015).
//!
//! A request object is a compact JWS signed by the client with a key from its
//! registered JWKS (the same keys used for `private_key_jwt`, ADR 0014). It is
//! verified with the shared `jose` verifier, then:
//!
//! - header `typ` is `oauth-authz-req+jwt` (RFC 9101 §10.8);
//! - `iss` and `client_id` equal the outer `client_id`;
//! - `aud` is, or contains, the AS issuer identifier;
//! - `exp` is required and at most [`REQUEST_OBJECT_MAX_LIFETIME_SECS`] ahead.
//!
//! The authorization parameters are taken only from the signed claims
//! (RFC 9101 §5); unsigned query parameters other than `client_id` are ignored.
//! Every failure is `invalid_request_object`.

use jose::jwks::Jwks;
use jose::json::Value;
use jose::verify::{self, Policy};

use crate::client_auth::CLIENT_ASSERTION_ALGS;
use crate::error::OAuthError;

/// Required request object `typ` (RFC 9101 §10.8).
pub const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// Largest accepted `exp - now` for a request object (seconds).
pub const REQUEST_OBJECT_MAX_LIFETIME_SECS: i64 = 300;

/// Largest accepted compact request object (bytes).
pub const REQUEST_OBJECT_MAX_BYTES: usize = 8192;

/// Authorization parameters carried by a verified request object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestObjectParams {
    pub response_type: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
}

/// Verifies a request object for `client_id` against the client's JWKS.
pub fn verify_request_object(
    request: &str,
    client_id: &str,
    client_jwks: &str,
    issuer: &str,
    now: i64,
) -> Result<RequestObjectParams, OAuthError> {
    let jwks =
        Jwks::parse(client_jwks.as_bytes()).map_err(|_| OAuthError::InvalidRequestObject)?;
    let verified = verify::verify(
        request.as_bytes(),
        &jwks,
        &Policy {
            algorithms: CLIENT_ASSERTION_ALGS.to_vec(),
            issuer: Some(client_id.to_owned()),
            audience: Some(issuer.to_owned()),
            now,
            leeway: 0,
            typ: Some(REQUEST_OBJECT_TYP.into()),
            max_token_bytes: REQUEST_OBJECT_MAX_BYTES,
        },
    )
    .map_err(|_| OAuthError::InvalidRequestObject)?;

    let claims = &verified.claims;
    if claims.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err(OAuthError::InvalidRequestObject);
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(OAuthError::InvalidRequestObject)?;
    if exp.saturating_sub(now) > REQUEST_OBJECT_MAX_LIFETIME_SECS {
        return Err(OAuthError::InvalidRequestObject);
    }
    // A request object must not nest another request (RFC 9101 §4).
    if claims.get("request").is_some() || claims.get("request_uri").is_some() {
        return Err(OAuthError::InvalidRequestObject);
    }

    let field = |name: &str| -> Result<Option<String>, OAuthError> {
        match claims.get(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(OAuthError::InvalidRequestObject),
        }
    };
    Ok(RequestObjectParams {
        response_type: field("response_type")?,
        redirect_uri: field("redirect_uri")?,
        code_challenge: field("code_challenge")?,
        code_challenge_method: field("code_challenge_method")?,
        state: field("state")?,
        scope: field("scope")?,
        nonce: field("nonce")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::alg::Alg;
    use jose::signing::{generate_signing_key, sign_compact, SigningKey};

    const AS: &str = "https://auth.example";

    fn setup() -> (SigningKey, String, String) {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let kid = key.public.thumbprint();
        let jwks = format!(
            r#"{{"keys":[{{"kid":"{kid}",{}]}}"#,
            &key.public.canonical_json()[1..]
        );
        (key, jwks, kid)
    }

    fn sign(key: &SigningKey, kid: &str, typ: &str, claims: &str) -> String {
        let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"{typ}"}}"#);
        sign_compact(Alg::EdDSA, &key.pkcs8, header.as_bytes(), claims.as_bytes()).unwrap()
    }

    fn claims(extra: &str) -> String {
        format!(
            r#"{{"iss":"svc","aud":"{AS}","client_id":"svc","exp":1060,"response_type":"code","redirect_uri":"https://svc.example/cb"{extra}}}"#
        )
    }

    #[test]
    fn returns_signed_params() {
        let (key, jwks, kid) = setup();
        let jwt = sign(&key, &kid, REQUEST_OBJECT_TYP, &claims(r#","state":"s1""#));
        let p = verify_request_object(&jwt, "svc", &jwks, AS, 1_000).unwrap();
        assert_eq!(p.response_type.as_deref(), Some("code"));
        assert_eq!(p.redirect_uri.as_deref(), Some("https://svc.example/cb"));
        assert_eq!(p.state.as_deref(), Some("s1"));
        assert_eq!(p.nonce, None);
    }

    #[test]
    fn rejects_bad_objects() {
        let (key, jwks, kid) = setup();
        let bad = [
            sign(&key, &kid, "JWT", &claims("")),
            sign(&key, &kid, REQUEST_OBJECT_TYP, &claims("").replace(r#""client_id":"svc""#, r#""client_id":"x""#)),
            sign(&key, &kid, REQUEST_OBJECT_TYP, &claims("").replace(r#""iss":"svc""#, r#""iss":"x""#)),
            sign(&key, &kid, REQUEST_OBJECT_TYP, &claims("").replace(AS, "https://evil.example")),
            sign(&key, &kid, REQUEST_OBJECT_TYP, &claims("").replace("1060", "1301")),
            sign(&key, &kid, REQUEST_OBJECT_TYP, &claims(r#","request_uri":"urn:x""#)),
            sign(&key, &kid, REQUEST_OBJECT_TYP, &claims(r#","state":7"#)),
        ];
        for jwt in bad {
            assert_eq!(
                verify_request_object(&jwt, "svc", &jwks, AS, 1_000),
                Err(OAuthError::InvalidRequestObject)
            );
        }
        let other = generate_signing_key(Alg::EdDSA).unwrap();
        let forged = sign(&other, &kid, REQUEST_OBJECT_TYP, &claims(""));
        assert_eq!(
            verify_request_object(&forged, "svc", &jwks, AS, 1_000),
            Err(OAuthError::InvalidRequestObject)
        );
    }
}
