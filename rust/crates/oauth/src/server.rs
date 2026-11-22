//! Authorization-code + PKCE orchestration (ADR 0005).

use std::sync::Mutex;

use jose::b64url;
use jose::jwk::PublicKey;
use jose::signing::SigningKey;

use crate::client::{Client, ClientRegistry};
use crate::code::{AuthorizationCode, CodeStore, DEFAULT_CODE_TTL_SECS};
use crate::error::OAuthError;
use crate::pkce::{self, require_s256_method};
use crate::token::{self, TokenClaims, DEFAULT_ACCESS_TOKEN_TTL_SECS};

/// Server configuration shared by the library and HTTP binder.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub issuer: String,
    pub audience: String,
    pub code_ttl_secs: i64,
    pub access_token_ttl_secs: i64,
}

impl ServerConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            code_ttl_secs: DEFAULT_CODE_TTL_SECS,
            access_token_ttl_secs: DEFAULT_ACCESS_TOKEN_TTL_SECS,
        }
    }
}

/// Validated authorize request awaiting stub login completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: Option<String>,
    pub scope: Option<String>,
}

/// Successful authorize redirect fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationSuccess {
    pub redirect_uri: String,
    pub code: String,
    pub state: Option<String>,
}

/// Token endpoint success body fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSuccess {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

/// Authorize query parameters (already decoded by the HTTP layer).
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: Option<String>,
    pub scope: Option<String>,
}

/// Token form parameters.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
}

/// In-memory authorization server.
pub struct AuthorizationServer {
    pub config: ServerConfig,
    pub clients: ClientRegistry,
    codes: Mutex<CodeStore>,
    pkcs8: Vec<u8>,
    public: PublicKey,
}

impl AuthorizationServer {
    pub fn new(config: ServerConfig, clients: Vec<Client>, signing: SigningKey) -> Self {
        Self {
            config,
            clients: ClientRegistry::new(clients),
            codes: Mutex::new(CodeStore::new()),
            pkcs8: signing.pkcs8,
            public: signing.public,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Builds a JWKS document containing the signing public key.
    pub fn jwks_document(&self) -> String {
        let kid = self.public.thumbprint();
        match &self.public {
            PublicKey::Ed25519 { x } => {
                format!(
                    r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{kid}","alg":"EdDSA","use":"sig"}}]}}"#,
                    b64url::encode(x)
                )
            }
            PublicKey::P256 { x, y } => {
                format!(
                    r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","kid":"{kid}","alg":"ES256","use":"sig"}}]}}"#,
                    b64url::encode(x),
                    b64url::encode(y)
                )
            }
        }
    }

    /// Validates authorize parameters. Does not issue a code until [`finish_authorize`].
    pub fn begin_authorize(&self, req: &AuthorizeRequest) -> Result<PendingAuthorization, OAuthError> {
        if req.response_type != "code" {
            return Err(OAuthError::InvalidRequest);
        }
        require_s256_method(&req.code_challenge_method)?;
        if req.code_challenge.is_empty() {
            return Err(OAuthError::InvalidRequest);
        }
        // Challenge is base64url of 32 bytes → typically 43 chars; accept non-empty for now
        // and enforce on verify via verifier rules.
        let client = self.clients.get(&req.client_id)?;
        if !client.allows_redirect(&req.redirect_uri) {
            // Do not redirect to an unregistered URI.
            return Err(OAuthError::InvalidRequest);
        }
        Ok(PendingAuthorization {
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            code_challenge: req.code_challenge.clone(),
            state: req.state.clone(),
            scope: req.scope.clone(),
        })
    }

    /// Issues a one-time code after stub login supplies `subject`.
    pub fn finish_authorize(
        &self,
        pending: PendingAuthorization,
        subject: &str,
        now: i64,
    ) -> Result<AuthorizationSuccess, OAuthError> {
        if subject.is_empty() {
            return Err(OAuthError::InvalidRequest);
        }
        let record = AuthorizationCode {
            client_id: pending.client_id,
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge,
            subject: subject.to_owned(),
            scope: pending.scope,
            expires_at: now.saturating_add(self.config.code_ttl_secs),
        };
        let mut store = self.codes.lock().map_err(|_| OAuthError::ServerError)?;
        let code = store.issue(record)?;
        Ok(AuthorizationSuccess {
            redirect_uri: pending.redirect_uri,
            code,
            state: pending.state,
        })
    }

    /// Exchanges an authorization code for an access token.
    pub fn exchange_token(&self, req: &TokenRequest, now: i64) -> Result<TokenSuccess, OAuthError> {
        if req.grant_type != "authorization_code" {
            return Err(OAuthError::UnsupportedGrantType);
        }
        // Ensure client exists (public client).
        self.clients.get(&req.client_id)?;

        let mut store = self.codes.lock().map_err(|_| OAuthError::ServerError)?;
        let record = store.redeem(&req.code, now)?;
        drop(store);

        if record.client_id != req.client_id || record.redirect_uri != req.redirect_uri {
            return Err(OAuthError::InvalidGrant);
        }
        pkce::verify_s256(&req.code_verifier, &record.code_challenge)?;

        let exp = now.saturating_add(self.config.access_token_ttl_secs);
        let access_token = token::mint_access_token(
            &self.pkcs8,
            &self.public,
            &TokenClaims {
                iss: &self.config.issuer,
                aud: &self.config.audience,
                sub: &record.subject,
                client_id: &record.client_id,
                scope: record.scope.as_deref(),
                iat: now,
                exp,
            },
        )?;

        Ok(TokenSuccess {
            access_token,
            token_type: "Bearer",
            expires_in: self.config.access_token_ttl_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::alg::Alg;
    use jose::jwks::Jwks;
    use jose::signing::generate_signing_key;
    use jose::verify::{self, Policy};

    fn server() -> AuthorizationServer {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        AuthorizationServer::new(
            ServerConfig::new("https://auth.example", "api"),
            vec![Client {
                client_id: "spa".into(),
                redirect_uris: vec!["https://app.example/cb".into()],
            }],
            key,
        )
    }

    fn pending(srv: &AuthorizationServer) -> PendingAuthorization {
        srv.begin_authorize(&AuthorizeRequest {
            response_type: "code".into(),
            client_id: "spa".into(),
            redirect_uri: "https://app.example/cb".into(),
            code_challenge: pkce::challenge_s256(&"a".repeat(43)).unwrap(),
            code_challenge_method: "S256".into(),
            state: Some("xyz".into()),
            scope: Some("read".into()),
        })
        .unwrap()
    }

    #[test]
    fn code_flow_issues_verifiable_access_token() {
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv.finish_authorize(p, "alice", 1_000).unwrap();
        assert_eq!(issued.state.as_deref(), Some("xyz"));

        let token = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued.code.clone(),
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: verifier,
                },
                1_001,
            )
            .unwrap();
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, DEFAULT_ACCESS_TOKEN_TTL_SECS);

        let jwks = Jwks::parse(srv.jwks_document().as_bytes()).unwrap();
        let verified = verify::verify(
            token.access_token.as_bytes(),
            &jwks,
            &Policy {
                algorithms: vec![Alg::EdDSA],
                issuer: Some("https://auth.example".into()),
                audience: Some("api".into()),
                now: 1_001,
                leeway: 0,
                typ: Some("at+jwt".into()),
                max_token_bytes: 8192,
            },
        )
        .unwrap();
        assert_eq!(verified.alg, Alg::EdDSA);
    }

    #[test]
    fn replayed_code_is_invalid_grant() {
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv.finish_authorize(p, "alice", 1_000).unwrap();
        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            code: issued.code,
            redirect_uri: "https://app.example/cb".into(),
            client_id: "spa".into(),
            code_verifier: verifier,
        };
        srv.exchange_token(&req, 1_001).unwrap();
        assert!(matches!(
            srv.exchange_token(&req, 1_002),
            Err(OAuthError::InvalidGrant)
        ));
    }

    #[test]
    fn plain_pkce_rejected() {
        let srv = server();
        let err = srv.begin_authorize(&AuthorizeRequest {
            response_type: "code".into(),
            client_id: "spa".into(),
            redirect_uri: "https://app.example/cb".into(),
            code_challenge: "x".into(),
            code_challenge_method: "plain".into(),
            state: None,
            scope: None,
        });
        assert_eq!(err, Err(OAuthError::InvalidRequest));
    }

    #[test]
    fn wrong_verifier_is_invalid_grant() {
        let srv = server();
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&"a".repeat(43)).unwrap();
        let issued = srv.finish_authorize(p, "alice", 1_000).unwrap();
        assert!(matches!(
            srv.exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: "b".repeat(43),
                },
                1_001,
            ),
            Err(OAuthError::InvalidGrant)
        ));
    }
}
