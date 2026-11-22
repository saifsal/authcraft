//! Authorization-code + PKCE + OIDC + refresh + PAR (ADR 0005–0009).

use std::sync::Mutex;

use jose::alg::Alg;
use jose::b64url;
use jose::jwk::PublicKey;
use jose::jwks::Jwks;
use jose::signing::SigningKey;
use jose::verify::{self, Policy};
use ring::rand::{SecureRandom, SystemRandom};

use crate::client::{Client, ClientRegistry};
use crate::code::{AuthorizationCode, CodeStore, DEFAULT_CODE_TTL_SECS};
use crate::denylist::JtiDenylist;
use crate::dpop::{self, DpopJtiCache};
use crate::error::OAuthError;
use crate::id_token::{self, IdTokenClaims};
use crate::keyring::{Keyring, DEFAULT_VERIFY_GRACE_SECS};
use crate::par::{ParRecord, ParStore, DEFAULT_PAR_TTL_SECS};
use crate::pkce::{self, require_s256_method};
use crate::refresh::{RefreshStore, DEFAULT_REFRESH_TOKEN_TTL_SECS};
use crate::token::{self, TokenClaims, DEFAULT_ACCESS_TOKEN_TTL_SECS};

/// Server configuration shared by the library and HTTP binder.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub issuer: String,
    pub audience: String,
    pub code_ttl_secs: i64,
    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,
    pub verify_grace_secs: i64,
    pub par_ttl_secs: i64,
}

impl ServerConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            code_ttl_secs: DEFAULT_CODE_TTL_SECS,
            access_token_ttl_secs: DEFAULT_ACCESS_TOKEN_TTL_SECS,
            refresh_token_ttl_secs: DEFAULT_REFRESH_TOKEN_TTL_SECS,
            verify_grace_secs: DEFAULT_VERIFY_GRACE_SECS,
            par_ttl_secs: DEFAULT_PAR_TTL_SECS,
        }
    }
}

/// Successful PAR response fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParSuccess {
    pub request_uri: String,
    pub expires_in: i64,
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
    pub refresh_token: Option<String>,
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
    /// When set, other authorize fields are loaded from the PAR store (ADR 0009).
    pub request_uri: Option<String>,
}

/// Token form parameters.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
    pub refresh_token: String,
}

/// UserInfo response claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

/// RFC 7662 introspection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Introspection {
    pub active: bool,
    pub client_id: Option<String>,
    pub sub: Option<String>,
    pub scope: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub token_type: Option<&'static str>,
}

impl Introspection {
    fn inactive() -> Self {
        Self {
            active: false,
            client_id: None,
            sub: None,
            scope: None,
            exp: None,
            iat: None,
            token_type: None,
        }
    }
}

/// Hint for revoke/introspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTypeHint {
    AccessToken,
    RefreshToken,
    None,
}

impl TokenTypeHint {
    pub fn parse(s: Option<&str>) -> Self {
        match s {
            Some("access_token") => Self::AccessToken,
            Some("refresh_token") => Self::RefreshToken,
            _ => Self::None,
        }
    }
}

/// In-memory authorization server.
pub struct AuthorizationServer {
    pub config: ServerConfig,
    pub clients: ClientRegistry,
    codes: Mutex<CodeStore>,
    refresh: Mutex<RefreshStore>,
    denylist: Mutex<JtiDenylist>,
    keys: Mutex<Keyring>,
    par: Mutex<ParStore>,
    dpop_jtis: Mutex<DpopJtiCache>,
}

impl AuthorizationServer {
    pub fn new(config: ServerConfig, clients: Vec<Client>, signing: SigningKey) -> Self {
        let grace = config.verify_grace_secs;
        Self {
            config,
            clients: ClientRegistry::new(clients),
            codes: Mutex::new(CodeStore::new()),
            refresh: Mutex::new(RefreshStore::new()),
            denylist: Mutex::new(JtiDenylist::new()),
            keys: Mutex::new(Keyring::from_signing_key(signing, grace)),
            par: Mutex::new(ParStore::new()),
            dpop_jtis: Mutex::new(DpopJtiCache::new()),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.keys
            .lock()
            .expect("keys lock")
            .current()
            .public
            .clone()
    }

    /// Builds a JWKS document containing all keys still within verify grace.
    pub fn jwks_document(&self) -> String {
        self.jwks_document_at(0)
    }

    pub fn jwks_document_at(&self, now: i64) -> String {
        self.keys
            .lock()
            .expect("keys lock")
            .jwks_document(now)
    }

    /// Rotates the signing key; previous key remains in JWKS until grace ends.
    pub fn rotate_signing_key(&self, now: i64) -> Result<(), OAuthError> {
        let mut keys = self.keys.lock().map_err(|_| OAuthError::ServerError)?;
        keys.rotate(now)
    }

    /// OpenID Provider metadata (ADR 0006).
    pub fn openid_configuration(&self) -> String {
        let iss = token::json_escape(&self.config.issuer);
        format!(
            r#"{{"issuer":"{iss}","authorization_endpoint":"{iss}/authorize","token_endpoint":"{iss}/token","userinfo_endpoint":"{iss}/userinfo","revocation_endpoint":"{iss}/revoke","introspection_endpoint":"{iss}/introspect","pushed_authorization_request_endpoint":"{iss}/par","require_pushed_authorization_requests":false,"dpop_signing_alg_values_supported":["EdDSA"],"jwks_uri":"{iss}/.well-known/jwks.json","response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"],"scopes_supported":["openid","profile","email"]}}"#
        )
    }

    fn verify_access_claims(
        &self,
        access_token: &str,
        now: i64,
    ) -> Result<jose::json::Value, OAuthError> {
        let jwks = Jwks::parse(self.jwks_document_at(now).as_bytes())
            .map_err(|_| OAuthError::ServerError)?;
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

        if let Some(jti) = verified.claims.get("jti").and_then(|v| v.as_str()) {
            let mut denylist = self.denylist.lock().map_err(|_| OAuthError::ServerError)?;
            if denylist.is_revoked(jti, now) {
                return Err(OAuthError::InvalidToken);
            }
        }
        Ok(verified.claims)
    }

    fn new_jti() -> Result<String, OAuthError> {
        let mut bytes = [0u8; 16];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| OAuthError::ServerError)?;
        Ok(b64url::encode(&bytes))
    }

    fn mint_access(
        &self,
        subject: &str,
        client_id: &str,
        scope: Option<&str>,
        name: Option<&str>,
        email: Option<&str>,
        cnf_jkt: Option<&str>,
        now: i64,
    ) -> Result<(String, i64), OAuthError> {
        let exp = now.saturating_add(self.config.access_token_ttl_secs);
        let jti = Self::new_jti()?;
        let keys = self.keys.lock().map_err(|_| OAuthError::ServerError)?;
        let current = keys.current();
        let access_token = token::mint_access_token(
            &current.pkcs8,
            &current.public,
            &TokenClaims {
                iss: &self.config.issuer,
                aud: &self.config.audience,
                sub: subject,
                client_id,
                jti: &jti,
                scope,
                name,
                email,
                cnf_jkt,
                iat: now,
                exp,
            },
        )?;
        Ok((access_token, exp))
    }

    fn resolve_dpop(
        &self,
        dpop_proof: Option<&str>,
        htu: &str,
        now: i64,
    ) -> Result<Option<String>, OAuthError> {
        let Some(proof) = dpop_proof.filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        let mut cache = self.dpop_jtis.lock().map_err(|_| OAuthError::ServerError)?;
        let verified = dpop::verify_proof(proof, "POST", htu, now, &mut cache)?;
        Ok(Some(verified.jkt))
    }

    /// Pushes authorize parameters and returns a one-time `request_uri` (ADR 0009).
    pub fn push_authorization(
        &self,
        req: &AuthorizeRequest,
        now: i64,
    ) -> Result<ParSuccess, OAuthError> {
        if req.request_uri.is_some() {
            return Err(OAuthError::InvalidRequest);
        }
        let pending = self.validate_authorize_params(req)?;
        let record = ParRecord {
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            code_challenge: req.code_challenge.clone(),
            code_challenge_method: req.code_challenge_method.clone(),
            response_type: req.response_type.clone(),
            state: pending.state,
            scope: pending.scope,
            nonce: pending.nonce,
            expires_at: now.saturating_add(self.config.par_ttl_secs),
        };
        let mut store = self.par.lock().map_err(|_| OAuthError::ServerError)?;
        let request_uri = store.issue(record)?;
        Ok(ParSuccess {
            request_uri,
            expires_in: self.config.par_ttl_secs,
        })
    }

    /// Validates authorize parameters. Does not issue a code until [`finish_authorize`].
    pub fn begin_authorize(
        &self,
        req: &AuthorizeRequest,
        now: i64,
    ) -> Result<PendingAuthorization, OAuthError> {
        if let Some(uri) = req.request_uri.as_deref() {
            if uri.is_empty() {
                return Err(OAuthError::InvalidRequest);
            }
            let mut store = self.par.lock().map_err(|_| OAuthError::ServerError)?;
            let record = store.redeem(uri, now)?;
            drop(store);
            if record.client_id != req.client_id {
                return Err(OAuthError::InvalidRequest);
            }
            let expanded = AuthorizeRequest {
                response_type: record.response_type,
                client_id: record.client_id,
                redirect_uri: record.redirect_uri,
                code_challenge: record.code_challenge,
                code_challenge_method: record.code_challenge_method,
                state: record.state,
                scope: record.scope,
                nonce: record.nonce,
                request_uri: None,
            };
            return self.validate_authorize_params(&expanded);
        }
        self.validate_authorize_params(req)
    }

    fn validate_authorize_params(
        &self,
        req: &AuthorizeRequest,
    ) -> Result<PendingAuthorization, OAuthError> {
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

    /// Exchanges an authorization code or refresh token (ADR 0008 / 0009).
    ///
    /// `dpop_proof` is the raw `DPoP` header value; `token_htu` is the absolute
    /// token endpoint URL (RFC 9449 `htu`).
    pub fn exchange_token(
        &self,
        req: &TokenRequest,
        now: i64,
        dpop_proof: Option<&str>,
        token_htu: &str,
    ) -> Result<TokenSuccess, OAuthError> {
        match req.grant_type.as_str() {
            "authorization_code" => {
                self.exchange_authorization_code(req, now, dpop_proof, token_htu)
            }
            "refresh_token" => self.exchange_refresh_token(req, now, dpop_proof, token_htu),
            _ => Err(OAuthError::UnsupportedGrantType),
        }
    }

    fn exchange_authorization_code(
        &self,
        req: &TokenRequest,
        now: i64,
        dpop_proof: Option<&str>,
        token_htu: &str,
    ) -> Result<TokenSuccess, OAuthError> {
        self.clients.get(&req.client_id)?;

        let mut store = self.codes.lock().map_err(|_| OAuthError::ServerError)?;
        let record = store.redeem(&req.code, now)?;
        drop(store);

        if record.client_id != req.client_id || record.redirect_uri != req.redirect_uri {
            return Err(OAuthError::InvalidGrant);
        }
        pkce::verify_s256(&req.code_verifier, &record.code_challenge)?;

        let jkt = self.resolve_dpop(dpop_proof, token_htu, now)?;
        let token_type = if jkt.is_some() { "DPoP" } else { "Bearer" };

        let (access_token, exp) = self.mint_access(
            &record.subject,
            &record.client_id,
            record.scope.as_deref(),
            record.name.as_deref(),
            record.email.as_deref(),
            jkt.as_deref(),
            now,
        )?;

        let id_token = if id_token::scope_has_openid(record.scope.as_deref()) {
            let nonce = record.nonce.as_deref().ok_or(OAuthError::ServerError)?;
            let at_hash = id_token::at_hash_eddsa(&access_token);
            let keys = self.keys.lock().map_err(|_| OAuthError::ServerError)?;
            let current = keys.current();
            Some(id_token::mint_id_token(
                &current.pkcs8,
                &current.public,
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

        let refresh_exp = now.saturating_add(self.config.refresh_token_ttl_secs);
        let mut refresh = self.refresh.lock().map_err(|_| OAuthError::ServerError)?;
        let refresh_token = refresh.issue_new_family(
            record.client_id.clone(),
            record.subject.clone(),
            record.scope.clone(),
            record.name.clone(),
            record.email.clone(),
            refresh_exp,
        )?;

        Ok(TokenSuccess {
            access_token,
            token_type,
            expires_in: self.config.access_token_ttl_secs,
            id_token,
            refresh_token: Some(refresh_token),
        })
    }

    fn exchange_refresh_token(
        &self,
        req: &TokenRequest,
        now: i64,
        dpop_proof: Option<&str>,
        token_htu: &str,
    ) -> Result<TokenSuccess, OAuthError> {
        self.clients.get(&req.client_id)?;
        if req.refresh_token.is_empty() {
            return Err(OAuthError::InvalidRequest);
        }

        let refresh_exp = now.saturating_add(self.config.refresh_token_ttl_secs);
        let mut store = self.refresh.lock().map_err(|_| OAuthError::ServerError)?;
        let (refresh_token, record) =
            store.rotate(&req.refresh_token, &req.client_id, now, refresh_exp)?;
        drop(store);

        let jkt = self.resolve_dpop(dpop_proof, token_htu, now)?;
        let token_type = if jkt.is_some() { "DPoP" } else { "Bearer" };

        let (access_token, _) = self.mint_access(
            &record.subject,
            &record.client_id,
            record.scope.as_deref(),
            record.name.as_deref(),
            record.email.as_deref(),
            jkt.as_deref(),
            now,
        )?;

        Ok(TokenSuccess {
            access_token,
            token_type,
            expires_in: self.config.access_token_ttl_secs,
            id_token: None,
            refresh_token: Some(refresh_token),
        })
    }

    /// Verifies an access token and returns UserInfo claims (ADR 0006 / 0008 / 0009).
    ///
    /// When the token has `cnf.jkt`, `dpop_proof` is required and must match.
    pub fn userinfo(
        &self,
        access_token: &str,
        now: i64,
        dpop_proof: Option<&str>,
        userinfo_htu: &str,
    ) -> Result<UserInfo, OAuthError> {
        let claims = self.verify_access_claims(access_token, now)?;
        if let Some(jkt) = claims
            .get("cnf")
            .and_then(|c| c.get("jkt"))
            .and_then(|v| v.as_str())
        {
            let proof = dpop_proof.filter(|p| !p.is_empty()).ok_or(OAuthError::InvalidToken)?;
            let mut cache = self.dpop_jtis.lock().map_err(|_| OAuthError::ServerError)?;
            let verified =
                dpop::verify_proof(proof, "GET", userinfo_htu, now, &mut cache)
                    .map_err(|_| OAuthError::InvalidToken)?;
            if verified.jkt != jkt {
                return Err(OAuthError::InvalidToken);
            }
        }
        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or(OAuthError::InvalidToken)?
            .to_owned();
        let name = claims.get("name").and_then(|v| v.as_str()).map(str::to_owned);
        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        Ok(UserInfo { sub, name, email })
    }

    /// RFC 7009 revoke. Unknown tokens succeed (caller maps to HTTP 200).
    pub fn revoke(
        &self,
        token: &str,
        hint: TokenTypeHint,
        client_id: &str,
        now: i64,
    ) -> Result<(), OAuthError> {
        let _ = self.clients.get(client_id)?;
        if token.is_empty() {
            return Ok(());
        }

        let try_refresh = matches!(hint, TokenTypeHint::RefreshToken | TokenTypeHint::None);
        let try_access = matches!(hint, TokenTypeHint::AccessToken | TokenTypeHint::None);

        if try_refresh {
            let mut store = self.refresh.lock().map_err(|_| OAuthError::ServerError)?;
            if let Some(rec) = store.get_active(token).cloned() {
                if rec.client_id == client_id {
                    store.revoke_family(&rec.family_id);
                    return Ok(());
                }
            }
        }

        if try_access {
            if let Ok(claims) = self.verify_access_claims(token, now) {
                let client_ok = claims
                    .get("client_id")
                    .and_then(|v| v.as_str())
                    == Some(client_id);
                if client_ok {
                    if let (Some(jti), Some(exp)) = (
                        claims.get("jti").and_then(|v| v.as_str()),
                        claims.get("exp").and_then(|v| v.as_i64()),
                    ) {
                        let mut denylist =
                            self.denylist.lock().map_err(|_| OAuthError::ServerError)?;
                        denylist.revoke(jti.to_owned(), exp);
                    }
                }
            }
        }
        Ok(())
    }

    /// RFC 7662 introspection (no client auth in this demo).
    pub fn introspect(
        &self,
        token: &str,
        hint: TokenTypeHint,
        now: i64,
    ) -> Result<Introspection, OAuthError> {
        if token.is_empty() {
            return Ok(Introspection::inactive());
        }

        let try_refresh = matches!(hint, TokenTypeHint::RefreshToken | TokenTypeHint::None);
        let try_access = matches!(hint, TokenTypeHint::AccessToken | TokenTypeHint::None);

        if try_refresh {
            let store = self.refresh.lock().map_err(|_| OAuthError::ServerError)?;
            if let Some(rec) = store.get_active(token) {
                if now < rec.expires_at {
                    return Ok(Introspection {
                        active: true,
                        client_id: Some(rec.client_id.clone()),
                        sub: Some(rec.subject.clone()),
                        scope: rec.scope.clone(),
                        exp: Some(rec.expires_at),
                        iat: None,
                        token_type: Some("refresh_token"),
                    });
                }
            }
            if matches!(hint, TokenTypeHint::RefreshToken) {
                return Ok(Introspection::inactive());
            }
        }

        if try_access {
            match self.verify_access_claims(token, now) {
                Ok(claims) => {
                    return Ok(Introspection {
                        active: true,
                        client_id: claims
                            .get("client_id")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned),
                        sub: claims.get("sub").and_then(|v| v.as_str()).map(str::to_owned),
                        scope: claims
                            .get("scope")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned),
                        exp: claims.get("exp").and_then(|v| v.as_i64()),
                        iat: claims.get("iat").and_then(|v| v.as_i64()),
                        token_type: Some("Bearer"),
                    });
                }
                Err(_) => return Ok(Introspection::inactive()),
            }
        }

        Ok(Introspection::inactive())
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
                    request_uri: None,
        }, 1_000)
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
                    refresh_token: String::new(),
                },
                1_001, None, "https://auth.example/token")
            .unwrap();
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, DEFAULT_ACCESS_TOKEN_TTL_SECS);
        assert!(token.id_token.is_none());
        assert!(token.refresh_token.is_some());

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
                        request_uri: None,
        }, 1_000)
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
                    refresh_token: String::new(),
                },
                1_001, None, "https://auth.example/token")
            .unwrap();
        let id_token = token.id_token.expect("id_token");
        assert!(token.refresh_token.is_some());
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

        let info = srv.userinfo(&token.access_token, 1_001, None, "https://auth.example/userinfo").unwrap();
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
                    request_uri: None,
        }, 1_000);
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
            refresh_token: String::new(),
        };
        srv.exchange_token(&req, 1_001, None, "https://auth.example/token").unwrap();
        assert!(matches!(
            srv.exchange_token(&req, 1_002, None, "https://auth.example/token"),
            Err(OAuthError::InvalidGrant)
        ));
    }

    #[test]
    fn refresh_rotates_and_reuse_is_invalid_grant() {
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
        let first = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: verifier,
                    refresh_token: String::new(),
                },
                1_001, None, "https://auth.example/token")
            .unwrap();
        let rt = first.refresh_token.expect("refresh");
        let second = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "refresh_token".into(),
                    code: String::new(),
                    redirect_uri: String::new(),
                    client_id: "spa".into(),
                    code_verifier: String::new(),
                    refresh_token: rt.clone(),
                },
                1_002, None, "https://auth.example/token")
            .unwrap();
        assert!(second.refresh_token.is_some());
        assert!(second.id_token.is_none());
        assert!(matches!(
            srv.exchange_token(
                &TokenRequest {
                    grant_type: "refresh_token".into(),
                    code: String::new(),
                    redirect_uri: String::new(),
                    client_id: "spa".into(),
                    code_verifier: String::new(),
                    refresh_token: rt,
                },
                1_003, None, "https://auth.example/token"),
            Err(OAuthError::InvalidGrant)
        ));
    }

    #[test]
    fn plain_pkce_rejected() {
        let srv = server();
        let err = srv.begin_authorize(
            &AuthorizeRequest {
                response_type: "code".into(),
                client_id: "spa".into(),
                redirect_uri: "https://app.example/cb".into(),
                code_challenge: "x".into(),
                code_challenge_method: "plain".into(),
                state: None,
                scope: None,
                nonce: None,
                request_uri: None,
            },
            1_000,
        );
        assert_eq!(err, Err(OAuthError::InvalidRequest));
    }

    #[test]
    fn par_then_authorize_and_replay_fails() {
        let srv = server();
        let challenge = pkce::challenge_s256(&"a".repeat(43)).unwrap();
        let pushed = srv
            .push_authorization(
                &AuthorizeRequest {
                    response_type: "code".into(),
                    client_id: "spa".into(),
                    redirect_uri: "https://app.example/cb".into(),
                    code_challenge: challenge,
                    code_challenge_method: "S256".into(),
                    state: Some("s".into()),
                    scope: Some("read".into()),
                    nonce: None,
                    request_uri: None,
                },
                1_000,
            )
            .unwrap();
        assert!(pushed.request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
        let pending = srv
            .begin_authorize(
                &AuthorizeRequest {
                    response_type: String::new(),
                    client_id: "spa".into(),
                    redirect_uri: String::new(),
                    code_challenge: String::new(),
                    code_challenge_method: String::new(),
                    state: None,
                    scope: None,
                    nonce: None,
                    request_uri: Some(pushed.request_uri.clone()),
                },
                1_001,
            )
            .unwrap();
        assert_eq!(pending.state.as_deref(), Some("s"));
        assert!(matches!(
            srv.begin_authorize(
                &AuthorizeRequest {
                    response_type: String::new(),
                    client_id: "spa".into(),
                    redirect_uri: String::new(),
                    code_challenge: String::new(),
                    code_challenge_method: String::new(),
                    state: None,
                    scope: None,
                    nonce: None,
                    request_uri: Some(pushed.request_uri),
                },
                1_002,
            ),
            Err(OAuthError::InvalidRequest)
        ));
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
                    refresh_token: String::new(),
                },
                1_001, None, "https://auth.example/token"),
            Err(OAuthError::InvalidGrant)
        ));
    }

    #[test]
    fn revoke_access_blocks_userinfo_and_introspect() {
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
        let tok = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: verifier,
                    refresh_token: String::new(),
                },
                1_001, None, "https://auth.example/token")
            .unwrap();
        assert!(srv
            .introspect(&tok.access_token, TokenTypeHint::AccessToken, 1_001)
            .unwrap()
            .active);
        srv.revoke(
            &tok.access_token,
            TokenTypeHint::AccessToken,
            "spa",
            1_001,
        )
        .unwrap();
        assert!(!srv
            .introspect(&tok.access_token, TokenTypeHint::AccessToken, 1_001)
            .unwrap()
            .active);
        assert!(matches!(
            srv.userinfo(&tok.access_token, 1_001, None, "https://auth.example/userinfo"),
            Err(OAuthError::InvalidToken)
        ));
    }

    #[test]
    fn rotate_signing_key_keeps_old_verifiable() {
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
        let first = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: verifier,
                    refresh_token: String::new(),
                },
                1_001, None, "https://auth.example/token")
            .unwrap();
        srv.rotate_signing_key(1_002).unwrap();
        let jwks = Jwks::parse(srv.jwks_document_at(1_002).as_bytes()).unwrap();
        verify::verify(
            first.access_token.as_bytes(),
            &jwks,
            &Policy {
                algorithms: vec![Alg::EdDSA],
                issuer: Some("https://auth.example".into()),
                audience: Some("api".into()),
                now: 1_002,
                leeway: 0,
                typ: Some("at+jwt".into()),
                max_token_bytes: 8192,
            },
        )
        .expect("old token verifies after rotate");

        let verifier2 = "b".repeat(43);
        let mut p2 = pending(&srv);
        p2.code_challenge = pkce::challenge_s256(&verifier2).unwrap();
        let issued2 = srv
            .finish_authorize(p2, &LoginSubject::new("bob"), 1_003)
            .unwrap();
        let second = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued2.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: verifier2,
                    refresh_token: String::new(),
                },
                1_004, None, "https://auth.example/token")
            .unwrap();
        verify::verify(
            second.access_token.as_bytes(),
            &jwks,
            &Policy {
                algorithms: vec![Alg::EdDSA],
                issuer: Some("https://auth.example".into()),
                audience: Some("api".into()),
                now: 1_004,
                leeway: 0,
                typ: Some("at+jwt".into()),
                max_token_bytes: 8192,
            },
        )
        .expect("new token verifies");

        // After grace, old key dropped: use a server with short grace.
        let mut cfg = ServerConfig::new("https://auth.example", "api");
        cfg.verify_grace_secs = 10;
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let short = AuthorizationServer::new(
            cfg,
            vec![Client {
                client_id: "spa".into(),
                redirect_uris: vec!["https://app.example/cb".into()],
            }],
            key,
        );
        let v = "c".repeat(43);
        let mut p3 = short
            .begin_authorize(&AuthorizeRequest {
                response_type: "code".into(),
                client_id: "spa".into(),
                redirect_uri: "https://app.example/cb".into(),
                code_challenge: pkce::challenge_s256(&v).unwrap(),
                code_challenge_method: "S256".into(),
                state: None,
                scope: Some("read".into()),
                nonce: None,
                        request_uri: None,
        }, 1_000)
            .unwrap();
        p3.code_challenge = pkce::challenge_s256(&v).unwrap();
        let issued3 = short
            .finish_authorize(p3, &LoginSubject::new("alice"), 2_000)
            .unwrap();
        let old = short
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued3.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: v,
                    refresh_token: String::new(),
                },
                2_001, None, "https://auth.example/token")
            .unwrap();
        short.rotate_signing_key(2_002).unwrap();
        let jwks_late = Jwks::parse(short.jwks_document_at(2_020).as_bytes()).unwrap();
        assert!(
            verify::verify(
                old.access_token.as_bytes(),
                &jwks_late,
                &Policy {
                    algorithms: vec![Alg::EdDSA],
                    issuer: Some("https://auth.example".into()),
                    audience: Some("api".into()),
                    now: 2_020,
                    leeway: 0,
                    typ: Some("at+jwt".into()),
                    max_token_bytes: 8192,
                },
            )
            .is_err(),
            "old key pruned from JWKS after grace"
        );
    }

    #[test]
    fn dpop_token_requires_proof_at_userinfo() {
        use jose::signing::{self, generate_signing_key as gen};
        let dpop_key = gen(Alg::EdDSA).unwrap();
        let jkt = dpop_key.public.thumbprint();
        let x = match &dpop_key.public {
            PublicKey::Ed25519 { x } => b64url::encode(x),
            _ => panic!(),
        };
        let header = format!(
            r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}}}"#
        );
        let payload =
            r#"{"htm":"POST","htu":"https://auth.example/token","iat":1001,"jti":"dpop-1"}"#;
        let enc_h = b64url::encode(header.as_bytes());
        let enc_p = b64url::encode(payload.as_bytes());
        let input = format!("{enc_h}.{enc_p}");
        let sig = signing::sign(Alg::EdDSA, &dpop_key.pkcs8, input.as_bytes()).unwrap();
        let proof = format!("{input}.{}", b64url::encode(&sig));

        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
        let tok = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: verifier,
                    refresh_token: String::new(),
                },
                1_001,
                Some(&proof),
                "https://auth.example/token",
            )
            .unwrap();
        assert_eq!(tok.token_type, "DPoP");
        assert!(matches!(
            srv.userinfo(
                &tok.access_token,
                1_001,
                None,
                "https://auth.example/userinfo"
            ),
            Err(OAuthError::InvalidToken)
        ));

        let payload2 =
            r#"{"htm":"GET","htu":"https://auth.example/userinfo","iat":1001,"jti":"dpop-2"}"#;
        let enc_p2 = b64url::encode(payload2.as_bytes());
        let input2 = format!("{enc_h}.{enc_p2}");
        let sig2 = signing::sign(Alg::EdDSA, &dpop_key.pkcs8, input2.as_bytes()).unwrap();
        let proof2 = format!("{input2}.{}", b64url::encode(&sig2));
        let info = srv
            .userinfo(
                &tok.access_token,
                1_001,
                Some(&proof2),
                "https://auth.example/userinfo",
            )
            .unwrap();
        assert_eq!(info.sub, "alice");
        let _ = jkt;
    }

    #[test]
    fn revoke_refresh_kills_family() {
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
        let tok = srv
            .exchange_token(
                &TokenRequest {
                    grant_type: "authorization_code".into(),
                    code: issued.code,
                    redirect_uri: "https://app.example/cb".into(),
                    client_id: "spa".into(),
                    code_verifier: verifier,
                    refresh_token: String::new(),
                },
                1_001, None, "https://auth.example/token")
            .unwrap();
        let rt = tok.refresh_token.unwrap();
        srv.revoke(&rt, TokenTypeHint::RefreshToken, "spa", 1_001)
            .unwrap();
        assert!(!srv
            .introspect(&rt, TokenTypeHint::RefreshToken, 1_001)
            .unwrap()
            .active);
        assert!(matches!(
            srv.exchange_token(
                &TokenRequest {
                    grant_type: "refresh_token".into(),
                    code: String::new(),
                    redirect_uri: String::new(),
                    client_id: "spa".into(),
                    code_verifier: String::new(),
                    refresh_token: rt,
                },
                1_002, None, "https://auth.example/token"),
            Err(OAuthError::InvalidGrant)
        ));
    }
}
