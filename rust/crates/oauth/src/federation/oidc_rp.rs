//! OIDC relying-party connector (ADR 0012 B1).

use jose::alg::Alg;
use jose::b64url;
use jose::jwks::Jwks;
use jose::verify::{self, Policy};
use ring::rand::{SecureRandom, SystemRandom};

use crate::pkce;
use crate::server::LoginSubject;
use crate::users::AuthnError;

/// Upstream OP client configuration.
#[derive(Debug, Clone)]
pub struct OidcRpConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: String,
}

/// Result of starting an outbound authorize redirect.
#[derive(Debug, Clone)]
pub struct OidcRpStart {
    pub authorize_url: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcRpError {
    Config,
    Token,
    IdToken,
    Nonce,
}

impl OidcRpError {
    pub fn code(self) -> &'static str {
        match self {
            OidcRpError::Config => "invalid_request",
            OidcRpError::Token => "invalid_grant",
            OidcRpError::IdToken => "invalid_token",
            OidcRpError::Nonce => "invalid_nonce",
        }
    }
}

impl From<OidcRpError> for AuthnError {
    fn from(_: OidcRpError) -> Self {
        AuthnError::InvalidCredentials
    }
}

fn random_b64url(n: usize) -> Result<String, OidcRpError> {
    let mut bytes = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OidcRpError::Config)?;
    Ok(b64url::encode(&bytes))
}

/// Build the upstream authorize URL (PKCE S256 + state + nonce).
pub fn start_oidc_login(
    cfg: &OidcRpConfig,
    authorization_endpoint: &str,
) -> Result<OidcRpStart, OidcRpError> {
    if cfg.issuer.is_empty() || cfg.client_id.is_empty() || cfg.redirect_uri.is_empty() {
        return Err(OidcRpError::Config);
    }
    let state = random_b64url(16)?;
    let nonce = random_b64url(16)?;
    // 43-byte verifier (unpadded base64url of 32 bytes).
    let code_verifier = random_b64url(32)?;
    let challenge = pkce::challenge_s256(&code_verifier).map_err(|_| OidcRpError::Config)?;
    let scopes = if cfg.scopes.is_empty() {
        "openid profile email"
    } else {
        cfg.scopes.as_str()
    };
    let mut url = format!(
        "{authorization_endpoint}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        urlencoding_encode(&cfg.client_id),
        urlencoding_encode(&cfg.redirect_uri),
        urlencoding_encode(scopes),
        urlencoding_encode(&state),
        urlencoding_encode(&nonce),
        urlencoding_encode(&challenge),
    );
    // Keep deterministic order; trim trailing if needed.
    let _ = &mut url;
    Ok(OidcRpStart {
        authorize_url: url,
        state,
        nonce,
        code_verifier,
    })
}

/// Verify an ID token and map claims to [`LoginSubject`].
pub fn login_subject_from_id_token(
    id_token: &str,
    jwks: &Jwks,
    cfg: &OidcRpConfig,
    expected_nonce: &str,
    now: i64,
) -> Result<LoginSubject, OidcRpError> {
    let verified = verify::verify(
        id_token.as_bytes(),
        jwks,
        &Policy {
            algorithms: vec![Alg::EdDSA, Alg::ES256],
            issuer: Some(cfg.issuer.clone()),
            audience: Some(cfg.client_id.clone()),
            now,
            leeway: 60,
            typ: None,
            max_token_bytes: 8192,
        },
    )
    .map_err(|_| OidcRpError::IdToken)?;

    let nonce = verified
        .claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(OidcRpError::Nonce)?;
    if nonce != expected_nonce {
        return Err(OidcRpError::Nonce);
    }

    let subject = verified
        .claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(OidcRpError::IdToken)?
        .to_owned();
    let name = verified
        .claims
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let email = verified
        .claims
        .get("email")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    Ok(LoginSubject {
        subject,
        name,
        email,
    })
}

/// Extract `id_token` from a token-endpoint JSON body (minimal parser).
pub fn id_token_from_token_response(body: &str) -> Result<String, OidcRpError> {
    // Prefer jose json for consistency.
    let root = jose::json::parse(body.as_bytes()).map_err(|_| OidcRpError::Token)?;
    root.get("id_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(OidcRpError::Token)
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::signing::{self, generate_signing_key};
    use jose::jwk::PublicKey;

    fn sign_id_token(
        iss: &str,
        aud: &str,
        sub: &str,
        nonce: &str,
        now: i64,
        kid: &str,
        key: &jose::signing::SigningKey,
    ) -> String {
        let header = format!(r#"{{"alg":"EdDSA","typ":"JWT","kid":"{kid}"}}"#);
        let payload = format!(
            r#"{{"iss":"{iss}","aud":"{aud}","sub":"{sub}","nonce":"{nonce}","exp":{},"iat":{now},"name":"Fed User","email":"fed@example.com"}}"#,
            now + 300
        );
        let enc_h = b64url::encode(header.as_bytes());
        let enc_p = b64url::encode(payload.as_bytes());
        let input = format!("{enc_h}.{enc_p}");
        let sig = signing::sign(Alg::EdDSA, &key.pkcs8, input.as_bytes()).unwrap();
        format!("{input}.{}", b64url::encode(&sig))
    }

    #[test]
    fn start_includes_pkce_and_nonce() {
        let cfg = OidcRpConfig {
            issuer: "https://idp.example".into(),
            client_id: "rp".into(),
            client_secret: None,
            redirect_uri: "http://localhost:8089/login/oidc/callback".into(),
            scopes: "openid".into(),
        };
        let start = start_oidc_login(&cfg, "https://idp.example/authorize").unwrap();
        assert!(start.authorize_url.contains("code_challenge_method=S256"));
        assert!(start.authorize_url.contains("nonce="));
        assert!(!start.code_verifier.is_empty());
    }

    #[test]
    fn id_token_maps_login_subject() {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let kid = "upstream-1";
        let now = 1_700_000_000;
        let nonce = "n1";
        let token = sign_id_token(
            "https://idp.example",
            "rp",
            "upstream-sub",
            nonce,
            now,
            kid,
            &key,
        );
        let jwks = match &key.public {
            PublicKey::Ed25519 { x } => {
                let x = b64url::encode(x);
                jose::jwks::Jwks::parse(
                    format!(
                        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}","kid":"{kid}","alg":"EdDSA","use":"sig"}}]}}"#
                    )
                    .as_bytes(),
                )
                .unwrap()
            }
            _ => panic!("eddsa"),
        };
        let cfg = OidcRpConfig {
            issuer: "https://idp.example".into(),
            client_id: "rp".into(),
            client_secret: None,
            redirect_uri: "http://localhost/cb".into(),
            scopes: "openid".into(),
        };
        let login = login_subject_from_id_token(&token, &jwks, &cfg, nonce, now).unwrap();
        assert_eq!(login.subject, "upstream-sub");
        assert_eq!(login.name.as_deref(), Some("Fed User"));
        assert_eq!(login.email.as_deref(), Some("fed@example.com"));
    }

    #[test]
    fn wrong_audience_rejected() {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let kid = "upstream-1";
        let now = 1_700_000_000;
        let token = sign_id_token("https://idp.example", "other", "s", "n", now, kid, &key);
        let jwks = match &key.public {
            PublicKey::Ed25519 { x } => {
                let x = b64url::encode(x);
                jose::jwks::Jwks::parse(
                    format!(
                        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}","kid":"{kid}","alg":"EdDSA","use":"sig"}}]}}"#
                    )
                    .as_bytes(),
                )
                .unwrap()
            }
            _ => panic!("eddsa"),
        };
        let cfg = OidcRpConfig {
            issuer: "https://idp.example".into(),
            client_id: "rp".into(),
            client_secret: None,
            redirect_uri: "http://localhost/cb".into(),
            scopes: "openid".into(),
        };
        assert!(login_subject_from_id_token(&token, &jwks, &cfg, "n", now).is_err());
    }
}
