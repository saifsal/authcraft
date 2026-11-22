//! Authorization-code + PKCE + OIDC orchestration (ADR 0005, ADR 0006).

use std::sync::Mutex;

use jose::alg::Alg;
use jose::b64url;
use jose::jwk::PublicKey;
use jose::jwks::Jwks;
use jose::signing::SigningKey;
use jose::verify::{self, Policy};

use crate::client::{Client, ClientRegistry};
use crate::code::{AuthorizationCode, CodeStore, DEFAULT_CODE_TTL_SECS};
use crate::error::OAuthError;
use crate::id_token::{self, IdTokenClaims};
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
    pub nonce: Option<String>,
}

/// Stub login subject and optional profile claims (ADR 0006).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSubject {
    pub subject: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

impl LoginSubject {
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            name: None,
            email: None,
        }
    }
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
    pub id_token: Option<String>,
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
    pub nonce: Option<String>,
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

/// UserInfo response claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub email: Option<String>,
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

    /// OpenID Provider metadata (ADR 0006).
    pub fn openid_configuration(&self) -> String {
        let iss = token::json_escape(&self.config.issuer);
        format!(
            r#"{{"issuer":"{iss}","authorization_endpoint":"{iss}/authorize","token_endpoint":"{iss}/token","userinfo_endpoint":"{iss}/userinfo","jwks_uri":"{iss}/.well-known/jwks.json","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"],"scopes_supported":["openid","profile","email"]}}"#
        )
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
        let client = self.clients.get(&req.client_id)?;
        if !client.allows_redirect(&req.redirect_uri) {
            return Err(OAuthError::InvalidRequest);
        }

        let openid = id_token::scope_has_openid(req.scope.as_deref());
        let nonce = if openid {
            let n = req.nonce.as_deref().unwrap_or("").trim();
            if n.is_empty() {
                return Err(OAuthError::InvalidRequest);
            }
            Some(n.to_owned())
        } else {
            None
        };

        Ok(PendingAuthorization {
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            code_challenge: req.code_challenge.clone(),
            state: req.state.clone(),
            scope: req.scope.clone(),
            nonce,
        })
    }

    /// Issues a one-time code after stub login supplies the subject.
    pub fn finish_authorize(
        &self,
        pending: PendingAuthorization,
        login: &LoginSubject,
        now: i64,
    ) -> Result<AuthorizationSuccess, OAuthError> {
        if login.subject.is_empty() {
            return Err(OAuthError::InvalidRequest);
        }
        let record = AuthorizationCode {
            client_id: pending.client_id,
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge,
            subject: login.subject.clone(),
            scope: pending.scope,
            nonce: pending.nonce,
            name: login.name.clone(),
            email: login.email.clone(),
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

    /// Exchanges an authorization code for an access token (and ID token when `openid`).
    pub fn exchange_token(&self, req: &TokenRequest, now: i64) -> Result<TokenSuccess, OAuthError> {
        if req.grant_type != "authorization_code" {
            return Err(OAuthError::UnsupportedGrantType);
        }
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
                name: record.name.as_deref(),
                email: record.email.as_deref(),
                iat: now,
                exp,
            },
        )?;

        let id_token = if id_token::scope_has_openid(record.scope.as_deref()) {
            let nonce = record.nonce.as_deref().ok_or(OAuthError::ServerError)?;
            let at_hash = id_token::at_hash_eddsa(&access_token);
            Some(id_token::mint_id_token(
                &self.pkcs8,
                &self.public,
                &IdTokenClaims {
                    iss: &self.config.issuer,
                    sub: &record.subject,
                    aud: &record.client_id,
                    nonce,
                    at_hash: &at_hash,
                    iat: now,
                    exp,
                    name: record.name.as_deref(),
                    email: record.email.as_deref(),
                },
            )?)
        } else {
            None
        };

        Ok(TokenSuccess {
            access_token,
            token_type: "Bearer",
            expires_in: self.config.access_token_ttl_secs,
            id_token,
        })
    }

    /// Verifies a Bearer access token and returns UserInfo claims (ADR 0006).
    pub fn userinfo(&self, access_token: &str, now: i64) -> Result<UserInfo, OAuthError> {
        let jwks = Jwks::parse(self.jwks_document().as_bytes()).map_err(|_| OAuthError::ServerError)?;
        let verified = verify::verify(
            access_token.as_bytes(),
            &jwks,
            &Policy {
                algorithms: vec![Alg::EdDSA],
                issuer: Some(self.config.issuer.clone()),
                audience: Some(self.config.audience.clone()),
                now,
                leeway: 0,
                typ: Some("at+jwt".into()),
                max_token_bytes: 8192,
            },
        )
        .map_err(|_| OAuthError::InvalidToken)?;

        let sub = verified
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or(OAuthError::InvalidToken)?
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
        Ok(UserInfo { sub, name, email })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::signing::generate_signing_key;

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
            nonce: None,
        })
        .unwrap()
    }

    #[test]
    fn code_flow_issues_verifiable_access_token() {
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
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
        assert!(token.id_token.is_none());

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
    fn openid_flow_issues_id_token_with_at_hash() {
        let srv = server();
        let verifier = "a".repeat(43);
        let challenge = pkce::challenge_s256(&verifier).unwrap();
        let pending = srv
            .begin_authorize(&AuthorizeRequest {
                response_type: "code".into(),
                client_id: "spa".into(),
                redirect_uri: "https://app.example/cb".into(),
                code_challenge: challenge,
                code_challenge_method: "S256".into(),
                state: None,
                scope: Some("openid profile".into()),
                nonce: Some("n-0S6_WzA2Mj".into()),
            })
            .unwrap();
        let issued = srv
            .finish_authorize(
                pending,
                &LoginSubject {
                    subject: "alice".into(),
                    name: Some("Alice".into()),
                    email: Some("alice@example.com".into()),
                },
                1_000,
            )
            .unwrap();
        let token = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: verifier,
                },
                1_001,
            )
            .unwrap();
        let id_token = token.id_token.expect("id_token");
        let expected_hash = id_token::at_hash_eddsa(&token.access_token);

        let jwks = Jwks::parse(srv.jwks_document().as_bytes()).unwrap();
        let verified = verify::verify(
            id_token.as_bytes(),
            &jwks,
            &Policy {
                algorithms: vec![Alg::EdDSA],
                issuer: Some("https://auth.example".into()),
                audience: Some("spa".into()),
                now: 1_001,
                leeway: 0,
                typ: Some("JWT".into()),
                max_token_bytes: 8192,
            },
        )
        .unwrap();
        assert_eq!(
            verified.claims.get("nonce").and_then(|v| v.as_str()),
            Some("n-0S6_WzA2Mj")
        );
        assert_eq!(
            verified.claims.get("at_hash").and_then(|v| v.as_str()),
            Some(expected_hash.as_str())
        );

        let info = srv.userinfo(&token.access_token, 1_001).unwrap();
        assert_eq!(info.sub, "alice");
        assert_eq!(info.name.as_deref(), Some("Alice"));
        assert_eq!(info.email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn openid_without_nonce_is_invalid_request() {
        let srv = server();
        let err = srv.begin_authorize(&AuthorizeRequest {
            response_type: "code".into(),
            client_id: "spa".into(),
            redirect_uri: "https://app.example/cb".into(),
            code_challenge: pkce::challenge_s256(&"a".repeat(43)).unwrap(),
            code_challenge_method: "S256".into(),
            state: None,
            scope: Some("openid".into()),
            nonce: None,
        });
        assert_eq!(err, Err(OAuthError::InvalidRequest));
    }

    #[test]
    fn replayed_code_is_invalid_grant() {
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
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
            nonce: None,
        });
        assert_eq!(err, Err(OAuthError::InvalidRequest));
    }

    #[test]
    fn wrong_verifier_is_invalid_grant() {
        let srv = server();
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&"a".repeat(43)).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
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
