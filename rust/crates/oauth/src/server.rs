//! Authorization-code + PKCE + OIDC + refresh + PAR (ADR 0005–0009).

use std::sync::Mutex;

use jose::alg::Alg;
use jose::b64url;
use jose::jwk::PublicKey;
use jose::jwks::Jwks;
use jose::signing::SigningKey;
use jose::verify::{self, Policy};
use ring::rand::{SecureRandom, SystemRandom};

use crate::client::{Client, ClientRegistry, TokenEndpointAuth};
use crate::client_auth::{self, ClientAssertionJtiCache, CLIENT_ASSERTION_TYPE_JWT_BEARER};
use crate::code::{AuthorizationCode, CodeStore, DEFAULT_CODE_TTL_SECS};
use crate::denylist::JtiDenylist;
use crate::dpop::{self, DpopJtiCache};
use crate::mtls;
use crate::error::OAuthError;
use crate::id_token::{self, IdTokenClaims};
use crate::keyring::{Keyring, DEFAULT_VERIFY_GRACE_SECS};
use crate::par::{ParRecord, ParStore, DEFAULT_PAR_TTL_SECS};
use crate::pkce::{self, require_s256_method};
use crate::request_object;
use crate::refresh::{RefreshStore, DEFAULT_REFRESH_TOKEN_TTL_SECS};
use crate::token::{self, TokenClaims, DEFAULT_ACCESS_TOKEN_TTL_SECS};
use crate::scim::{self, ScimUser};
use crate::totp;
use crate::users::{AuthnError, UserRecord, UserStore};
use crate::webauthn_mfa::WebauthnMfa;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

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
    /// When true, `/authorize` requires `request_uri` from PAR (RFC 9126).
    pub require_par: bool,
    /// WebAuthn RP ID (e.g. `localhost`).
    pub rp_id: String,
    /// WebAuthn RP origin (e.g. `http://localhost:8089`).
    pub rp_origin: String,
    /// Bearer token for `/admin` and SCIM (ADR 0011). Empty disables admin.
    pub admin_token: String,
    /// When true, client assertions must carry header
    /// `typ: client-authentication+jwt` (ADR 0014 B3).
    pub require_client_assertion_typ: bool,
}

/// Published demo admin bearer token (educational only).
pub const DEMO_ADMIN_TOKEN: &str = "authcraft-admin-token";

impl ServerConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        let issuer = issuer.into();
        let rp_origin = issuer.clone();
        let rp_id = url::Url::parse(&issuer)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "localhost".into());
        Self {
            issuer,
            audience: audience.into(),
            code_ttl_secs: DEFAULT_CODE_TTL_SECS,
            access_token_ttl_secs: DEFAULT_ACCESS_TOKEN_TTL_SECS,
            refresh_token_ttl_secs: DEFAULT_REFRESH_TOKEN_TTL_SECS,
            verify_grace_secs: DEFAULT_VERIFY_GRACE_SECS,
            par_ttl_secs: DEFAULT_PAR_TTL_SECS,
            require_par: false,
            rp_id,
            rp_origin,
            admin_token: String::new(),
            require_client_assertion_typ: false,
        }
    }
}

/// Successful PAR response fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParSuccess {
    pub request_uri: String,
    pub expires_in: i64,
}

/// TOTP enrollment material (shown once).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpEnrollment {
    pub secret_b32: String,
    pub otpauth_uri: String,
}

/// RFC 7591 dynamic client registration request (ADR 0011 B2 / ADR 0014).
#[derive(Debug, Clone)]
pub struct DynamicClientRequest {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    /// `none` (default) or `private_key_jwt`.
    pub token_endpoint_auth_method: Option<String>,
    /// Inline public JWKS document; required for `private_key_jwt` only.
    pub jwks: Option<String>,
    /// RFC 9101 §10.5; requires `private_key_jwt` (ADR 0015 B2).
    pub require_signed_request_object: bool,
}

/// RFC 7591 registration response fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicClientSuccess {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub token_endpoint_auth_method: &'static str,
    pub require_signed_request_object: bool,
}

/// Validated authorize request awaiting resource-owner authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
}

/// Authenticated subject and optional profile claims (ADR 0006 / ADR 0010).
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
    /// RFC 9207 issuer identifier (mix-up mitigation).
    pub iss: String,
}

/// Token endpoint success body fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSuccess {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    /// Next `DPoP-Nonce` value when this response used DPoP (RFC 9449).
    pub dpop_nonce: Option<String>,
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
    /// RFC 9101 request object (JAR, ADR 0015). When set, the other authorize
    /// fields except `client_id` are taken from its signed claims.
    pub request: Option<String>,
}

/// Client credentials presented to a back-channel endpoint (`/par`,
/// `/revoke`, `/introspect`): an RFC 7523 assertion for `private_key_jwt`
/// clients (ADR 0014) and/or the TLS client certificate for
/// `self_signed_tls_client_auth` (ADR 0017). Public clients leave the
/// assertion fields `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientCredentials {
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    /// DER bytes of the TLS client leaf certificate, if the connection had one.
    pub tls_client_cert: Option<Vec<u8>>,
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
    /// RFC 7523 `client_assertion_type` (confidential clients, ADR 0014).
    pub client_assertion_type: Option<String>,
    /// RFC 7523 `client_assertion` JWT (confidential clients, ADR 0014).
    pub client_assertion: Option<String>,
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

/// Admin / control-plane errors (ADR 0011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminError {
    Unauthorized,
    NotFound,
    Conflict,
    InvalidRequest,
}

impl AdminError {
    pub fn code(self) -> &'static str {
        match self {
            AdminError::Unauthorized => "unauthorized",
            AdminError::NotFound => "not_found",
            AdminError::Conflict => "conflict",
            AdminError::InvalidRequest => "invalid_request",
        }
    }
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for AdminError {}

/// Public user summary for admin listing (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSummary {
    pub username: String,
    pub subject: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub totp_enrolled: bool,
    pub webauthn_enrolled: bool,
}

/// In-memory authorization server.
pub struct AuthorizationServer {
    pub config: ServerConfig,
    clients: Mutex<ClientRegistry>,
    codes: Mutex<CodeStore>,
    refresh: Mutex<RefreshStore>,
    denylist: Mutex<JtiDenylist>,
    keys: Mutex<Keyring>,
    par: Mutex<ParStore>,
    dpop_jtis: Mutex<DpopJtiCache>,
    client_assertion_jtis: Mutex<ClientAssertionJtiCache>,
    /// Current AS-issued DPoP nonce (RFC 9449).
    dpop_nonce: Mutex<String>,
    users: Mutex<UserStore>,
    webauthn: WebauthnMfa,
}

impl AuthorizationServer {
    pub fn new(config: ServerConfig, clients: Vec<Client>, signing: SigningKey) -> Self {
        let grace = config.verify_grace_secs;
        let webauthn = WebauthnMfa::new(&config.rp_id, &config.rp_origin)
            .expect("webauthn rp configuration");
        Self {
            config,
            clients: Mutex::new(ClientRegistry::new(clients)),
            codes: Mutex::new(CodeStore::new()),
            refresh: Mutex::new(RefreshStore::new()),
            denylist: Mutex::new(JtiDenylist::new()),
            keys: Mutex::new(Keyring::from_signing_key(signing, grace)),
            par: Mutex::new(ParStore::new()),
            dpop_jtis: Mutex::new(DpopJtiCache::new()),
            client_assertion_jtis: Mutex::new(ClientAssertionJtiCache::new()),
            dpop_nonce: Mutex::new(String::new()),
            users: Mutex::new(UserStore::new()),
            webauthn,
        }
    }

    /// Current `DPoP-Nonce` value for challenge responses (creates one if empty).
    pub fn dpop_nonce(&self) -> Result<String, OAuthError> {
        self.ensure_dpop_nonce()
    }

    fn ensure_dpop_nonce(&self) -> Result<String, OAuthError> {
        let mut slot = self.dpop_nonce.lock().map_err(|_| OAuthError::ServerError)?;
        if slot.is_empty() {
            *slot = Self::new_jti()?;
        }
        Ok(slot.clone())
    }

    fn rotate_dpop_nonce(&self) -> Result<String, OAuthError> {
        let mut slot = self.dpop_nonce.lock().map_err(|_| OAuthError::ServerError)?;
        *slot = Self::new_jti()?;
        Ok(slot.clone())
    }

    fn require_admin(&self, token: Option<&str>) -> Result<(), AdminError> {
        let expected = self.config.admin_token.as_str();
        if expected.is_empty() {
            return Err(AdminError::Unauthorized);
        }
        match token {
            Some(t) if t == expected => Ok(()),
            _ => Err(AdminError::Unauthorized),
        }
    }

    fn lookup_client(&self, client_id: &str) -> Result<Client, OAuthError> {
        self.clients
            .lock()
            .expect("clients lock")
            .get(client_id)
            .cloned()
    }

    /// Back-channel client authentication at `/token`, `/par`, `/revoke` (ADR 0014).
    ///
    /// Public clients must not send a client assertion. `private_key_jwt`
    /// clients must send a valid, unused RFC 7523 assertion. Runs before any
    /// code, refresh token, or DPoP proof is consumed.
    fn authenticate_client(
        &self,
        client_id: &str,
        assertion_type: Option<&str>,
        assertion: Option<&str>,
        tls_client_cert: Option<&[u8]>,
        now: i64,
    ) -> Result<Client, OAuthError> {
        let client = self.lookup_client(client_id)?;
        match &client.token_endpoint_auth {
            TokenEndpointAuth::SelfSignedTlsClientAuth { cert_thumbprints } => {
                // RFC 8705 §2.2: the certificate is the credential; mixing in
                // an assertion is ambiguous and refused.
                if assertion_type.is_some() || assertion.is_some() {
                    return Err(OAuthError::InvalidClient);
                }
                let presented = tls_client_cert
                    .map(mtls::cert_thumbprint)
                    .ok_or(OAuthError::InvalidClient)?;
                if !cert_thumbprints.contains(&presented) {
                    return Err(OAuthError::InvalidClient);
                }
            }
            TokenEndpointAuth::None => {
                if assertion_type.is_some() || assertion.is_some() {
                    return Err(OAuthError::InvalidClient);
                }
            }
            TokenEndpointAuth::PrivateKeyJwt { jwks } => {
                if assertion_type != Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) {
                    return Err(OAuthError::InvalidClient);
                }
                let assertion = assertion
                    .filter(|a| !a.is_empty())
                    .ok_or(OAuthError::InvalidClient)?;
                let mut cache = self
                    .client_assertion_jtis
                    .lock()
                    .map_err(|_| OAuthError::ServerError)?;
                client_auth::verify_client_assertion(
                    assertion,
                    &client.client_id,
                    jwks,
                    &self.config.issuer,
                    now,
                    self.config.require_client_assertion_typ,
                    &mut cache,
                )?;
            }
        }
        Ok(client)
    }

    fn validate_client_metadata(client: &Client) -> bool {
        match &client.token_endpoint_auth {
            // Request objects are verified with a signing JWKS (ADR 0015).
            TokenEndpointAuth::SelfSignedTlsClientAuth { cert_thumbprints } => {
                !cert_thumbprints.is_empty() && !client.require_signed_request_object
            }
            // A public client has no keys to sign request objects with and
            // cannot authenticate to the introspection endpoint.
            TokenEndpointAuth::None => {
                !client.require_signed_request_object && !client.resource_server
            }
            TokenEndpointAuth::PrivateKeyJwt { jwks } => client_auth::parse_client_jwks(jwks).is_ok(),
        }
    }

    /// List registered clients (admin).
    pub fn list_clients(&self, admin_token: Option<&str>) -> Result<Vec<Client>, AdminError> {
        self.require_admin(admin_token)?;
        Ok(self.clients.lock().expect("clients lock").list().to_vec())
    }

    /// Create a client (admin). A `private_key_jwt` client needs a non-empty JWKS.
    /// A resource server (ADR 0016) may have no redirect URIs.
    pub fn create_client(
        &self,
        admin_token: Option<&str>,
        client: Client,
    ) -> Result<Client, AdminError> {
        self.require_admin(admin_token)?;
        if client.client_id.trim().is_empty()
            || (client.redirect_uris.is_empty() && !client.resource_server)
            || !Self::validate_client_metadata(&client)
        {
            return Err(AdminError::InvalidRequest);
        }
        let mut reg = self.clients.lock().expect("clients lock");
        if !reg.insert(client.clone()) {
            return Err(AdminError::Conflict);
        }
        Ok(client)
    }

    /// Delete a client by id (admin).
    pub fn delete_client(
        &self,
        admin_token: Option<&str>,
        client_id: &str,
    ) -> Result<(), AdminError> {
        self.require_admin(admin_token)?;
        if self.clients.lock().expect("clients lock").remove(client_id) {
            Ok(())
        } else {
            Err(AdminError::NotFound)
        }
    }

    /// List users without password material (admin).
    pub fn list_users(&self, admin_token: Option<&str>) -> Result<Vec<UserSummary>, AdminError> {
        self.require_admin(admin_token)?;
        let users = self.users.lock().expect("users lock");
        Ok(users
            .iter()
            .map(|(username, u)| UserSummary {
                username: username.clone(),
                subject: u.subject.clone(),
                name: u.name.clone(),
                email: u.email.clone(),
                totp_enrolled: u.totp_secret.is_some(),
                webauthn_enrolled: u.webauthn_enrolled(),
            })
            .collect())
    }

    /// SCIM create User (admin).
    pub fn scim_create_user(
        &self,
        admin_token: Option<&str>,
        body: &[u8],
    ) -> Result<ScimUser, AdminError> {
        self.require_admin(admin_token)?;
        let input = scim::parse_user_json(body)?;
        let record = scim::build_user_record(&input, None)?;
        let mut users = self.users.lock().expect("users lock");
        if users.get(&input.user_name).is_some() {
            return Err(AdminError::Conflict);
        }
        let scim_user = ScimUser::from_record(&input.user_name, &record);
        users.insert(input.user_name, record);
        Ok(scim_user)
    }

    pub fn scim_get_user(
        &self,
        admin_token: Option<&str>,
        id: &str,
    ) -> Result<ScimUser, AdminError> {
        self.require_admin(admin_token)?;
        let uuid = Uuid::parse_str(id).map_err(|_| AdminError::NotFound)?;
        let users = self.users.lock().expect("users lock");
        let (name, record) = users.get_by_handle(uuid).ok_or(AdminError::NotFound)?;
        Ok(ScimUser::from_record(name, record))
    }

    pub fn scim_list_users(
        &self,
        admin_token: Option<&str>,
        filter: Option<&str>,
    ) -> Result<Vec<ScimUser>, AdminError> {
        self.require_admin(admin_token)?;
        let only = scim::parse_username_filter(filter)?;
        let users = self.users.lock().expect("users lock");
        let mut out = Vec::new();
        for (name, record) in users.iter() {
            if let Some(ref want) = only {
                if name != want {
                    continue;
                }
            }
            out.push(ScimUser::from_record(name, record));
        }
        Ok(out)
    }

    pub fn scim_replace_user(
        &self,
        admin_token: Option<&str>,
        id: &str,
        body: &[u8],
    ) -> Result<ScimUser, AdminError> {
        self.require_admin(admin_token)?;
        let uuid = Uuid::parse_str(id).map_err(|_| AdminError::NotFound)?;
        let input = scim::parse_user_json(body)?;
        let mut users = self.users.lock().expect("users lock");
        let (old_name, existing) = {
            let (n, r) = users.get_by_handle(uuid).ok_or(AdminError::NotFound)?;
            (n.to_owned(), r.clone())
        };
        if input.user_name != old_name && users.get(&input.user_name).is_some() {
            return Err(AdminError::Conflict);
        }
        let record = scim::build_user_record(&input, Some(&existing))?;
        let scim_user = ScimUser::from_record(&input.user_name, &record);
        if input.user_name != old_name {
            users.remove(&old_name);
        }
        users.insert(input.user_name, record);
        Ok(scim_user)
    }

    pub fn scim_delete_user(
        &self,
        admin_token: Option<&str>,
        id: &str,
    ) -> Result<(), AdminError> {
        self.require_admin(admin_token)?;
        let uuid = Uuid::parse_str(id).map_err(|_| AdminError::NotFound)?;
        let mut users = self.users.lock().expect("users lock");
        let name = users
            .username_for_handle(uuid)
            .ok_or(AdminError::NotFound)?
            .to_owned();
        users.remove(&name);
        Ok(())
    }

    /// Insert or replace a user account (ADR 0010).
    pub fn upsert_user(&self, username: impl Into<String>, record: UserRecord) {
        self.users
            .lock()
            .expect("users lock")
            .insert(username, record);
    }

    /// Seed the published demo user `alice`.
    pub fn seed_demo_users(&self) {
        self.users.lock().expect("users lock").seed_demo_alice();
    }

    /// Verify username + password; returns [`LoginSubject`] on success.
    pub fn authenticate_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LoginSubject, AuthnError> {
        self.users
            .lock()
            .expect("users lock")
            .authenticate_password(username, password)
    }

    /// Whether the user has any second factor enrolled (TOTP / WebAuthn).
    pub fn user_mfa_enrolled(&self, username: &str) -> bool {
        self.users
            .lock()
            .expect("users lock")
            .get(username.trim())
            .map(UserRecord::mfa_enrolled)
            .unwrap_or(false)
    }

    /// Whether TOTP is enrolled for `username`.
    pub fn user_totp_enrolled(&self, username: &str) -> bool {
        self.users
            .lock()
            .expect("users lock")
            .totp_secret(username)
            .is_some()
    }

    /// Enroll TOTP for an existing user; returns base32 secret and otpauth URI.
    pub fn enroll_totp(
        &self,
        username: &str,
        issuer: &str,
    ) -> Result<TotpEnrollment, AuthnError> {
        let secret = totp::generate_secret()?;
        let secret_b32 = totp::encode_base32(&secret);
        let otpauth_uri = totp::otpauth_uri(issuer, username.trim(), &secret_b32);
        self.users
            .lock()
            .expect("users lock")
            .set_totp_secret(username, secret_b32.clone())?;
        Ok(TotpEnrollment {
            secret_b32,
            otpauth_uri,
        })
    }

    /// Set a known TOTP secret (tests / vectors).
    pub fn set_totp_secret(&self, username: &str, secret_b32: &str) -> Result<(), AuthnError> {
        self.users
            .lock()
            .expect("users lock")
            .set_totp_secret(username, secret_b32.to_owned())
    }

    /// Verify a TOTP code for `username` at `now`.
    pub fn verify_totp(&self, username: &str, code: &str, now: i64) -> Result<(), AuthnError> {
        let secret_b32 = self
            .users
            .lock()
            .expect("users lock")
            .totp_secret(username)
            .ok_or(AuthnError::InvalidMfa)?;
        let secret = totp::decode_base32(&secret_b32)?;
        if totp::verify_code(&secret, code, now) {
            Ok(())
        } else {
            Err(AuthnError::InvalidMfa)
        }
    }

    pub fn user_webauthn_enrolled(&self, username: &str) -> bool {
        self.users
            .lock()
            .expect("users lock")
            .get(username.trim())
            .map(UserRecord::webauthn_enrolled)
            .unwrap_or(false)
    }

    /// Begin WebAuthn security-key registration (after password check by caller).
    pub fn webauthn_start_registration(
        &self,
        username: &str,
    ) -> Result<CreationChallengeResponse, AuthnError> {
        let users = self.users.lock().expect("users lock");
        let user = users.get(username.trim()).ok_or(AuthnError::InvalidCredentials)?;
        let display = user
            .name
            .clone()
            .unwrap_or_else(|| user.subject.clone());
        let handle = user.user_handle;
        let existing = user.webauthn_credentials.clone();
        drop(users);
        self.webauthn
            .start_registration(username.trim(), handle, &display, existing)
    }

    pub fn webauthn_finish_registration(
        &self,
        username: &str,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<(), AuthnError> {
        let sk = self.webauthn.finish_registration(username.trim(), reg)?;
        let mut users = self.users.lock().expect("users lock");
        let user = users
            .get_mut(username.trim())
            .ok_or(AuthnError::InvalidCredentials)?;
        user.webauthn_credentials.push(sk);
        Ok(())
    }

    pub fn webauthn_start_authentication(
        &self,
        session_key: &str,
        username: &str,
    ) -> Result<RequestChallengeResponse, AuthnError> {
        let users = self.users.lock().expect("users lock");
        let user = users.get(username.trim()).ok_or(AuthnError::InvalidMfa)?;
        if user.webauthn_credentials.is_empty() {
            return Err(AuthnError::InvalidMfa);
        }
        let creds = user.webauthn_credentials.clone();
        drop(users);
        self.webauthn.start_authentication(session_key, &creds)
    }

    pub fn webauthn_finish_authentication(
        &self,
        session_key: &str,
        username: &str,
        auth: &PublicKeyCredential,
    ) -> Result<(), AuthnError> {
        let mut users = self.users.lock().expect("users lock");
        let user = users
            .get_mut(username.trim())
            .ok_or(AuthnError::InvalidMfa)?;
        self.webauthn
            .finish_authentication(session_key, auth, &mut user.webauthn_credentials)
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
            r#"{{"issuer":"{iss}","authorization_endpoint":"{iss}/authorize","token_endpoint":"{iss}/token","userinfo_endpoint":"{iss}/userinfo","revocation_endpoint":"{iss}/revoke","introspection_endpoint":"{iss}/introspect","registration_endpoint":"{iss}/register","pushed_authorization_request_endpoint":"{iss}/par","require_pushed_authorization_requests":{require_par},"authorization_response_iss_parameter_supported":true,"request_parameter_supported":true,"request_uri_parameter_supported":false,"request_object_signing_alg_values_supported":["EdDSA","ES256"],"dpop_signing_alg_values_supported":["EdDSA"],"jwks_uri":"{iss}/.well-known/jwks.json","response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none","private_key_jwt","self_signed_tls_client_auth"],"token_endpoint_auth_signing_alg_values_supported":["EdDSA","ES256"],"revocation_endpoint_auth_methods_supported":["none","private_key_jwt","self_signed_tls_client_auth"],"introspection_endpoint_auth_methods_supported":["private_key_jwt","self_signed_tls_client_auth"],"tls_client_certificate_bound_access_tokens":true,"scopes_supported":["openid","profile","email"]}}"#,
            require_par = if self.config.require_par {
                "true"
            } else {
                "false"
            },
        )
    }

    /// RFC 7591 dynamic registration (ADR 0011 B2). `private_key_jwt` clients
    /// supply an inline `jwks` (ADR 0014); `jwks_uri` is not supported.
    pub fn register_client(
        &self,
        req: &DynamicClientRequest,
    ) -> Result<DynamicClientSuccess, OAuthError> {
        if req.redirect_uris.is_empty()
            || req.redirect_uris.iter().any(|u| u.trim().is_empty())
        {
            return Err(OAuthError::InvalidRequest);
        }
        let token_endpoint_auth = match (req.token_endpoint_auth_method.as_deref(), &req.jwks) {
            (None | Some("none"), None) => TokenEndpointAuth::None,
            (Some("private_key_jwt"), Some(jwks)) => {
                client_auth::parse_client_jwks(jwks)?;
                TokenEndpointAuth::PrivateKeyJwt { jwks: jwks.clone() }
            }
            (Some("self_signed_tls_client_auth"), Some(jwks)) => {
                TokenEndpointAuth::SelfSignedTlsClientAuth {
                    cert_thumbprints: mtls::thumbprints_from_jwks(jwks)?,
                }
            }
            _ => return Err(OAuthError::InvalidRequest),
        };
        let token_endpoint_auth_method = token_endpoint_auth.method();
        let client_id = Self::new_jti().map_err(|_| OAuthError::ServerError)?;
        let client = Client {
            client_id: client_id.clone(),
            redirect_uris: req.redirect_uris.clone(),
            client_name: req.client_name.clone(),
            token_endpoint_auth,
            require_signed_request_object: req.require_signed_request_object,
            // RFC 7591 registration cannot grant the resource-server role.
            resource_server: false,
        };
        if !Self::validate_client_metadata(&client) {
            return Err(OAuthError::InvalidRequest);
        }
        if !self.clients.lock().expect("clients lock").insert(client) {
            return Err(OAuthError::ServerError);
        }
        Ok(DynamicClientSuccess {
            client_id,
            redirect_uris: req.redirect_uris.clone(),
            client_name: req.client_name.clone(),
            token_endpoint_auth_method,
            require_signed_request_object: req.require_signed_request_object,
        })
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

    #[allow(clippy::too_many_arguments)]
    fn mint_access(
        &self,
        subject: &str,
        client_id: &str,
        scope: Option<&str>,
        name: Option<&str>,
        email: Option<&str>,
        cnf_jkt: Option<&str>,
        cnf_x5t_s256: Option<&str>,
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
                cnf_x5t_s256,
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
    ) -> Result<(Option<String>, Option<String>), OAuthError> {
        let Some(proof) = dpop_proof.filter(|p| !p.is_empty()) else {
            return Ok((None, None));
        };
        let expected = self.ensure_dpop_nonce()?;
        let mut cache = self.dpop_jtis.lock().map_err(|_| OAuthError::ServerError)?;
        let verified =
            dpop::verify_proof(proof, "POST", htu, now, &mut cache, Some(&expected))?;
        drop(cache);
        let next = self.rotate_dpop_nonce()?;
        Ok((Some(verified.jkt), Some(next)))
    }

    /// Rejects plain (unsigned) authorize parameters for a client registered
    /// with `require_signed_request_object` (ADR 0015 B2). Unknown clients pass
    /// here and fail later in [`Self::validate_authorize_params`].
    fn check_signed_request_required(&self, req: &AuthorizeRequest) -> Result<(), OAuthError> {
        if req.request.is_some() {
            return Ok(());
        }
        match self.lookup_client(&req.client_id) {
            Ok(client) if client.require_signed_request_object => Err(OAuthError::InvalidRequest),
            _ => Ok(()),
        }
    }

    /// Replaces authorize parameters with the claims of a verified RFC 9101
    /// request object (ADR 0015). Without `request`, returns `req` unchanged.
    fn expand_request_object(
        &self,
        req: &AuthorizeRequest,
        now: i64,
    ) -> Result<AuthorizeRequest, OAuthError> {
        let Some(jwt) = req.request.as_deref() else {
            return Ok(req.clone());
        };
        if req.request_uri.is_some() || jwt.is_empty() {
            return Err(OAuthError::InvalidRequest);
        }
        let client = self.lookup_client(&req.client_id)?;
        // Only clients with a registered JWKS can sign request objects.
        let TokenEndpointAuth::PrivateKeyJwt { jwks } = &client.token_endpoint_auth else {
            return Err(OAuthError::InvalidRequestObject);
        };
        let p = request_object::verify_request_object(
            jwt,
            &req.client_id,
            jwks,
            &self.config.issuer,
            now,
        )?;
        Ok(AuthorizeRequest {
            response_type: p.response_type.unwrap_or_default(),
            client_id: req.client_id.clone(),
            redirect_uri: p.redirect_uri.unwrap_or_default(),
            code_challenge: p.code_challenge.unwrap_or_default(),
            code_challenge_method: p.code_challenge_method.unwrap_or_default(),
            state: p.state,
            scope: p.scope,
            nonce: p.nonce,
            request_uri: None,
            request: None,
        })
    }

    /// Pushes authorize parameters and returns a one-time `request_uri` (ADR 0009).
    ///
    /// `private_key_jwt` clients authenticate with `client_auth` (RFC 9126 §2,
    /// ADR 0014) before the parameters are validated.
    pub fn push_authorization(
        &self,
        req: &AuthorizeRequest,
        client_auth: &ClientCredentials,
        now: i64,
    ) -> Result<ParSuccess, OAuthError> {
        self.authenticate_client(
            &req.client_id,
            client_auth.client_assertion_type.as_deref(),
            client_auth.client_assertion.as_deref(),
            client_auth.tls_client_cert.as_deref(),
            now,
        )?;
        if req.request_uri.is_some() {
            return Err(OAuthError::InvalidRequest);
        }
        self.check_signed_request_required(req)?;
        let req = &self.expand_request_object(req, now)?;
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
            if uri.is_empty() || req.request.is_some() {
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
                request: None,
            };
            return self.validate_authorize_params(&expanded);
        }
        if self.config.require_par {
            return Err(OAuthError::InvalidRequest);
        }
        self.check_signed_request_required(req)?;
        let req = self.expand_request_object(req, now)?;
        self.validate_authorize_params(&req)
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
        let client = self.lookup_client(&req.client_id)?;
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
            iss: self.config.issuer.clone(),
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
        self.exchange_token_tls(req, now, dpop_proof, token_htu, None)
    }

    /// [`Self::exchange_token`] over a TLS connection that may carry a client
    /// certificate (RFC 8705, ADR 0017). The certificate authenticates
    /// `self_signed_tls_client_auth` clients and, when no DPoP proof is sent,
    /// binds the access token (`cnf.x5t#S256`) and refresh family to it.
    pub fn exchange_token_tls(
        &self,
        req: &TokenRequest,
        now: i64,
        dpop_proof: Option<&str>,
        token_htu: &str,
        tls_client_cert: Option<&[u8]>,
    ) -> Result<TokenSuccess, OAuthError> {
        match req.grant_type.as_str() {
            "authorization_code" => self.exchange_authorization_code(
                req,
                now,
                dpop_proof,
                token_htu,
                tls_client_cert,
            ),
            "refresh_token" => {
                self.exchange_refresh_token(req, now, dpop_proof, token_htu, tls_client_cert)
            }
            _ => Err(OAuthError::UnsupportedGrantType),
        }
    }

    fn exchange_authorization_code(
        &self,
        req: &TokenRequest,
        now: i64,
        dpop_proof: Option<&str>,
        token_htu: &str,
        tls_client_cert: Option<&[u8]>,
    ) -> Result<TokenSuccess, OAuthError> {
        self.authenticate_client(
            &req.client_id,
            req.client_assertion_type.as_deref(),
            req.client_assertion.as_deref(),
            tls_client_cert,
            now,
        )?;

        // DPoP (including nonce challenge) before redeem so `use_dpop_nonce`
        // does not consume the authorization code.
        let (jkt, dpop_nonce) = self.resolve_dpop(dpop_proof, token_htu, now)?;
        let token_type = if jkt.is_some() { "DPoP" } else { "Bearer" };
        // RFC 8705 §3: bind to the TLS certificate unless DPoP already binds.
        let x5t = if jkt.is_none() {
            tls_client_cert.map(mtls::cert_thumbprint)
        } else {
            None
        };

        let mut store = self.codes.lock().map_err(|_| OAuthError::ServerError)?;
        let record = store.redeem(&req.code, now)?;
        drop(store);

        if record.client_id != req.client_id || record.redirect_uri != req.redirect_uri {
            return Err(OAuthError::InvalidGrant);
        }
        pkce::verify_s256(&req.code_verifier, &record.code_challenge)?;

        let (access_token, exp) = self.mint_access(
            &record.subject,
            &record.client_id,
            record.scope.as_deref(),
            record.name.as_deref(),
            record.email.as_deref(),
            jkt.as_deref(),
            x5t.as_deref(),
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
            jkt.clone(),
            x5t,
        )?;

        Ok(TokenSuccess {
            access_token,
            token_type,
            expires_in: self.config.access_token_ttl_secs,
            id_token,
            refresh_token: Some(refresh_token),
            dpop_nonce,
        })
    }

    fn exchange_refresh_token(
        &self,
        req: &TokenRequest,
        now: i64,
        dpop_proof: Option<&str>,
        token_htu: &str,
        tls_client_cert: Option<&[u8]>,
    ) -> Result<TokenSuccess, OAuthError> {
        self.authenticate_client(
            &req.client_id,
            req.client_assertion_type.as_deref(),
            req.client_assertion.as_deref(),
            tls_client_cert,
            now,
        )?;
        if req.refresh_token.is_empty() {
            return Err(OAuthError::InvalidRequest);
        }

        // Verify DPoP against the bound jkt before rotate so a failed proof
        // does not consume the presented refresh token.
        let (bound_jkt, bound_x5t) = {
            let store = self.refresh.lock().map_err(|_| OAuthError::ServerError)?;
            store
                .get_active(&req.refresh_token)
                .map(|r| (r.dpop_jkt.clone(), r.mtls_x5t.clone()))
                .unwrap_or_default()
        };
        let presented_x5t = tls_client_cert.map(mtls::cert_thumbprint);
        if let Some(bound) = bound_x5t.as_deref() {
            if presented_x5t.as_deref() != Some(bound) {
                return Err(OAuthError::InvalidGrant);
            }
        }
        let (jkt, dpop_nonce) = self.resolve_dpop(dpop_proof, token_htu, now)?;
        if let Some(bound) = bound_jkt.as_deref() {
            match jkt.as_deref() {
                Some(presented) if presented == bound => {}
                _ => return Err(OAuthError::InvalidGrant),
            }
        }

        let refresh_exp = now.saturating_add(self.config.refresh_token_ttl_secs);
        let mut store = self.refresh.lock().map_err(|_| OAuthError::ServerError)?;
        let (refresh_token, record) =
            store.rotate(&req.refresh_token, &req.client_id, now, refresh_exp)?;
        drop(store);

        let token_type = if jkt.is_some() { "DPoP" } else { "Bearer" };
        let x5t = if jkt.is_none() { presented_x5t } else { None };

        let (access_token, _) = self.mint_access(
            &record.subject,
            &record.client_id,
            record.scope.as_deref(),
            record.name.as_deref(),
            record.email.as_deref(),
            jkt.as_deref(),
            x5t.as_deref(),
            now,
        )?;

        Ok(TokenSuccess {
            access_token,
            token_type,
            expires_in: self.config.access_token_ttl_secs,
            id_token: None,
            refresh_token: Some(refresh_token),
            dpop_nonce,
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
        self.userinfo_tls(access_token, now, dpop_proof, userinfo_htu, None)
    }

    /// [`Self::userinfo`] with the caller's TLS client certificate. A token
    /// with `cnf.x5t#S256` requires the matching certificate (RFC 8705 §3).
    pub fn userinfo_tls(
        &self,
        access_token: &str,
        now: i64,
        dpop_proof: Option<&str>,
        userinfo_htu: &str,
        tls_client_cert: Option<&[u8]>,
    ) -> Result<UserInfo, OAuthError> {
        let claims = self.verify_access_claims(access_token, now)?;
        if let Some(x5t) = claims
            .get("cnf")
            .and_then(|c| c.get("x5t#S256"))
            .and_then(|v| v.as_str())
        {
            if tls_client_cert.map(mtls::cert_thumbprint).as_deref() != Some(x5t) {
                return Err(OAuthError::InvalidToken);
            }
        }
        if let Some(jkt) = claims
            .get("cnf")
            .and_then(|c| c.get("jkt"))
            .and_then(|v| v.as_str())
        {
            let proof = dpop_proof.filter(|p| !p.is_empty()).ok_or(OAuthError::InvalidToken)?;
            let expected = self.ensure_dpop_nonce()?;
            let mut cache = self.dpop_jtis.lock().map_err(|_| OAuthError::ServerError)?;
            let verified = match dpop::verify_proof(
                proof,
                "GET",
                userinfo_htu,
                now,
                &mut cache,
                Some(&expected),
            ) {
                Ok(v) => v,
                Err(OAuthError::UseDpopNonce) => return Err(OAuthError::UseDpopNonce),
                Err(_) => return Err(OAuthError::InvalidToken),
            };
            if verified.jkt != jkt {
                return Err(OAuthError::InvalidToken);
            }
            drop(cache);
            let _ = self.rotate_dpop_nonce()?;
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
        client_auth: &ClientCredentials,
        now: i64,
    ) -> Result<(), OAuthError> {
        // RFC 7009 §2.1: confidential clients authenticate (ADR 0014).
        self.authenticate_client(
            client_id,
            client_auth.client_assertion_type.as_deref(),
            client_auth.client_assertion.as_deref(),
            client_auth.tls_client_cert.as_deref(),
            now,
        )?;
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

    /// RFC 7662 introspection (ADR 0016).
    ///
    /// The caller must authenticate as a `private_key_jwt` client. A client
    /// flagged `resource_server` sees any token; any other client sees only
    /// tokens issued to itself, and every other token reads as inactive.
    pub fn introspect(
        &self,
        token: &str,
        hint: TokenTypeHint,
        caller_client_id: &str,
        client_auth: &ClientCredentials,
        now: i64,
    ) -> Result<Introspection, OAuthError> {
        let caller = self.authenticate_client(
            caller_client_id,
            client_auth.client_assertion_type.as_deref(),
            client_auth.client_assertion.as_deref(),
            client_auth.tls_client_cert.as_deref(),
            now,
        )?;
        if caller.token_endpoint_auth == TokenEndpointAuth::None {
            // Public clients cannot authenticate (RFC 7662 §2.1).
            return Err(OAuthError::InvalidClient);
        }
        let info = self.introspect_token(token, hint, now)?;
        if info.active
            && !caller.resource_server
            && info.client_id.as_deref() != Some(caller.client_id.as_str())
        {
            return Ok(Introspection::inactive());
        }
        Ok(info)
    }

    /// Token state lookup behind [`Self::introspect`], without caller checks.
    fn introspect_token(
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
            vec![Client::new("spa", vec!["https://app.example/cb".into()])],
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
                    request: None,
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
                    client_assertion_type: None,
                    client_assertion: None,
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
                        request: None,
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
                    client_assertion_type: None,
                    client_assertion: None,
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
                    request: None,
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
            client_assertion_type: None,
            client_assertion: None,
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
                    client_assertion_type: None,
                    client_assertion: None,
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
                    client_assertion_type: None,
                    client_assertion: None,
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
                    client_assertion_type: None,
                    client_assertion: None,
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
                request: None,
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
                    request: None,
                },
                &ClientCredentials::default(),
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
                    request: None,
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
                    request: None,
                },
                1_002,
            ),
            Err(OAuthError::InvalidRequest)
        ));
    }

    #[test]
    fn require_par_rejects_front_channel_params() {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let mut cfg = ServerConfig::new("https://auth.example", "api");
        cfg.require_par = true;
        let srv = AuthorizationServer::new(
            cfg,
            vec![Client::new("spa", vec!["https://app.example/cb".into()])],
            key,
        );
        assert!(srv
            .openid_configuration()
            .contains("\"require_pushed_authorization_requests\":true"));
        let challenge = pkce::challenge_s256(&"a".repeat(43)).unwrap();
        assert_eq!(
            srv.begin_authorize(
                &AuthorizeRequest {
                    response_type: "code".into(),
                    client_id: "spa".into(),
                    redirect_uri: "https://app.example/cb".into(),
                    code_challenge: challenge.clone(),
                    code_challenge_method: "S256".into(),
                    state: None,
                    scope: None,
                    nonce: None,
                    request_uri: None,
                    request: None,
                },
                1_000,
            ),
            Err(OAuthError::InvalidRequest)
        );
        let pushed = srv
            .push_authorization(
                &AuthorizeRequest {
                    response_type: "code".into(),
                    client_id: "spa".into(),
                    redirect_uri: "https://app.example/cb".into(),
                    code_challenge: challenge,
                    code_challenge_method: "S256".into(),
                    state: None,
                    scope: None,
                    nonce: None,
                    request_uri: None,
                    request: None,
                },
                &ClientCredentials::default(),
                1_000,
            )
            .unwrap();
        assert!(srv
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
                    request_uri: Some(pushed.request_uri),
                    request: None,
                },
                1_001,
            )
            .is_ok());
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
                    client_assertion_type: None,
                    client_assertion: None,
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
                    client_assertion_type: None,
                    client_assertion: None,
                },
                1_001, None, "https://auth.example/token")
            .unwrap();
        assert!(srv
            .introspect_token(&tok.access_token, TokenTypeHint::AccessToken, 1_001)
            .unwrap()
            .active);
        srv.revoke(
            &tok.access_token,
            TokenTypeHint::AccessToken,
            "spa", &ClientCredentials::default(),
            1_001,
        )
        .unwrap();
        assert!(!srv
            .introspect_token(&tok.access_token, TokenTypeHint::AccessToken, 1_001)
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
                    client_assertion_type: None,
                    client_assertion: None,
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
                    client_assertion_type: None,
                    client_assertion: None,
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
            vec![Client::new("spa", vec!["https://app.example/cb".into()])],
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
                        request: None,
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
                    client_assertion_type: None,
                    client_assertion: None,
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

    fn sign_dpop_proof(
        key: &SigningKey,
        htm: &str,
        htu: &str,
        iat: i64,
        jti: &str,
        nonce: Option<&str>,
    ) -> String {
        use jose::signing;
        let x = match &key.public {
            PublicKey::Ed25519 { x } => b64url::encode(x),
            _ => panic!(),
        };
        let header = format!(
            r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}}}"#
        );
        let payload = match nonce {
            Some(n) => format!(
                r#"{{"htm":"{htm}","htu":"{htu}","iat":{iat},"jti":"{jti}","nonce":"{n}"}}"#
            ),
            None => format!(r#"{{"htm":"{htm}","htu":"{htu}","iat":{iat},"jti":"{jti}"}}"#),
        };
        let enc_h = b64url::encode(header.as_bytes());
        let enc_p = b64url::encode(payload.as_bytes());
        let input = format!("{enc_h}.{enc_p}");
        let sig = signing::sign(Alg::EdDSA, &key.pkcs8, input.as_bytes()).unwrap();
        format!("{input}.{}", b64url::encode(&sig))
    }

    fn exchange_with_dpop_nonce(
        srv: &AuthorizationServer,
        req: &TokenRequest,
        now: i64,
        htu: &str,
        key: &SigningKey,
        jti: &str,
    ) -> TokenSuccess {
        let probe = sign_dpop_proof(key, "POST", htu, now, &format!("{jti}-probe"), None);
        match srv.exchange_token(req, now, Some(&probe), htu) {
            Err(OAuthError::UseDpopNonce) => {
                let n = srv.dpop_nonce().unwrap();
                let proof = sign_dpop_proof(key, "POST", htu, now, jti, Some(&n));
                srv.exchange_token(req, now, Some(&proof), htu).unwrap()
            }
            Ok(t) => t,
            Err(e) => panic!("unexpected {e}"),
        }
    }

    #[test]
    fn dpop_token_requires_proof_at_userinfo() {
        use jose::signing::generate_signing_key as gen;
        let dpop_key = gen(Alg::EdDSA).unwrap();
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
        let tok = exchange_with_dpop_nonce(
            &srv,
            &TokenRequest {
                grant_type: "authorization_code".into(),
                code: issued.code,
                redirect_uri: "https://app.example/cb".into(),
                client_id: "spa".into(),
                code_verifier: verifier,
                refresh_token: String::new(),
                client_assertion_type: None,
                client_assertion: None,
            },
            1_001,
            "https://auth.example/token",
            &dpop_key,
            "dpop-1",
        );
        assert_eq!(tok.token_type, "DPoP");
        assert!(tok.dpop_nonce.is_some());
        assert!(matches!(
            srv.userinfo(
                &tok.access_token,
                1_001,
                None,
                "https://auth.example/userinfo"
            ),
            Err(OAuthError::InvalidToken)
        ));

        let ui_nonce = tok.dpop_nonce.clone().unwrap();
        let proof2 = sign_dpop_proof(
            &dpop_key,
            "GET",
            "https://auth.example/userinfo",
            1_001,
            "dpop-2",
            Some(&ui_nonce),
        );
        let info = srv
            .userinfo(
                &tok.access_token,
                1_001,
                Some(&proof2),
                "https://auth.example/userinfo",
            )
            .unwrap();
        assert_eq!(info.sub, "alice");
    }

    #[test]
    fn dpop_bound_refresh_accepts_matching_proof() {
        use jose::signing::generate_signing_key as gen;
        let dpop_key = gen(Alg::EdDSA).unwrap();
        let srv = server();
        let verifier = "a".repeat(43);
        let mut p = pending(&srv);
        p.code_challenge = pkce::challenge_s256(&verifier).unwrap();
        let issued = srv
            .finish_authorize(p, &LoginSubject::new("alice"), 1_000)
            .unwrap();
        let tok = exchange_with_dpop_nonce(
            &srv,
            &TokenRequest {
                grant_type: "authorization_code".into(),
                code: issued.code,
                redirect_uri: "https://app.example/cb".into(),
                client_id: "spa".into(),
                code_verifier: verifier,
                refresh_token: String::new(),
                client_assertion_type: None,
                client_assertion: None,
            },
            1_001,
            "https://auth.example/token",
            &dpop_key,
            "code-1",
        );
        let rt = tok.refresh_token.unwrap();
        let rotated = exchange_with_dpop_nonce(
            &srv,
            &TokenRequest {
                grant_type: "refresh_token".into(),
                code: String::new(),
                redirect_uri: String::new(),
                client_id: "spa".into(),
                code_verifier: String::new(),
                refresh_token: rt,
                client_assertion_type: None,
                client_assertion: None,
            },
            1_001,
            "https://auth.example/token",
            &dpop_key,
            "rt-ok",
        );
        assert_eq!(rotated.token_type, "DPoP");
        assert!(rotated.refresh_token.is_some());
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
                    client_assertion_type: None,
                    client_assertion: None,
                },
                1_001, None, "https://auth.example/token")
            .unwrap();
        let rt = tok.refresh_token.unwrap();
        srv.revoke(&rt, TokenTypeHint::RefreshToken, "spa", &ClientCredentials::default(), 1_001)
            .unwrap();
        assert!(!srv
            .introspect_token(&rt, TokenTypeHint::RefreshToken, 1_001)
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
                    client_assertion_type: None,
                    client_assertion: None,
                },
                1_002, None, "https://auth.example/token"),
            Err(OAuthError::InvalidGrant)
        ));
    }

    fn confidential_server() -> (AuthorizationServer, SigningKey) {
        let client_key = generate_signing_key(Alg::EdDSA).unwrap();
        let kid = client_key.public.thumbprint();
        let canonical = client_key.public.canonical_json();
        let jwks = format!(r#"{{"keys":[{{"kid":"{kid}",{}]}}"#, &canonical[1..]);
        let srv = AuthorizationServer::new(
            ServerConfig::new("https://auth.example", "api"),
            vec![Client::private_key_jwt(
                "svc",
                vec!["https://svc.example/cb".into()],
                jwks,
            )],
            generate_signing_key(Alg::EdDSA).unwrap(),
        );
        (srv, client_key)
    }

    fn client_assertion(key: &SigningKey, aud: &str, jti: &str, exp: i64) -> String {
        let kid = key.public.thumbprint();
        let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#);
        let payload =
            format!(r#"{{"iss":"svc","sub":"svc","aud":"{aud}","jti":"{jti}","exp":{exp}}}"#);
        jose::signing::sign_compact(Alg::EdDSA, &key.pkcs8, header.as_bytes(), payload.as_bytes())
            .unwrap()
    }

    #[test]
    fn failed_client_auth_does_not_consume_code_and_refresh_requires_auth() {
        let (srv, key) = confidential_server();
        let verifier = "c".repeat(43);
        let pending = srv
            .begin_authorize(
                &AuthorizeRequest {
                    response_type: "code".into(),
                    client_id: "svc".into(),
                    redirect_uri: "https://svc.example/cb".into(),
                    code_challenge: pkce::challenge_s256(&verifier).unwrap(),
                    code_challenge_method: "S256".into(),
                    state: None,
                    scope: Some("read".into()),
                    nonce: None,
                    request_uri: None,
                    request: None,
                },
                1_000,
            )
            .unwrap();
        let code = srv
            .finish_authorize(pending, &LoginSubject::new("alice"), 1_000)
            .unwrap()
            .code;
        let req = |assertion: Option<String>, grant: &str, refresh: String| TokenRequest {
            grant_type: grant.into(),
            code: code.clone(),
            redirect_uri: "https://svc.example/cb".into(),
            client_id: "svc".into(),
            code_verifier: verifier.clone(),
            refresh_token: refresh,
            client_assertion_type: assertion
                .as_ref()
                .map(|_| CLIENT_ASSERTION_TYPE_JWT_BEARER.to_owned()),
            client_assertion: assertion,
        };
        let htu = "https://auth.example/token";

        let bad = client_assertion(&key, htu, "j0", 1_060);
        assert_eq!(
            srv.exchange_token(&req(Some(bad), "authorization_code", String::new()), 1_001, None, htu),
            Err(OAuthError::InvalidClient)
        );
        let good = client_assertion(&key, "https://auth.example", "j1", 1_060);
        let tok = srv
            .exchange_token(&req(Some(good), "authorization_code", String::new()), 1_001, None, htu)
            .unwrap();
        let rt = tok.refresh_token.unwrap();

        assert_eq!(
            srv.exchange_token(&req(None, "refresh_token", rt.clone()), 1_002, None, htu),
            Err(OAuthError::InvalidClient)
        );
        let good2 = client_assertion(&key, "https://auth.example", "j2", 1_060);
        let rt = srv
            .exchange_token(&req(Some(good2), "refresh_token", rt), 1_002, None, htu)
            .unwrap()
            .refresh_token
            .unwrap();

        // RFC 7009: revocation needs client authentication too.
        assert_eq!(
            srv.revoke(&rt, TokenTypeHint::RefreshToken, "svc", &ClientCredentials::default(), 1_003),
            Err(OAuthError::InvalidClient)
        );
        assert!(srv.introspect_token(&rt, TokenTypeHint::RefreshToken, 1_003).unwrap().active);
        let auth = ClientCredentials {
            client_assertion_type: Some(CLIENT_ASSERTION_TYPE_JWT_BEARER.into()),
            client_assertion: Some(client_assertion(&key, "https://auth.example", "j3", 1_060)),
            tls_client_cert: None,
        };
        srv.revoke(&rt, TokenTypeHint::RefreshToken, "svc", &auth, 1_003)
            .unwrap();
        assert!(!srv.introspect_token(&rt, TokenTypeHint::RefreshToken, 1_003).unwrap().active);
    }

    #[test]
    fn discovery_and_registration_advertise_private_key_jwt() {
        let srv = server();
        let doc = srv.openid_configuration();
        assert!(doc.contains(
            r#""token_endpoint_auth_methods_supported":["none","private_key_jwt","self_signed_tls_client_auth"]"#
        ));
        assert!(doc.contains(r#""tls_client_certificate_bound_access_tokens":true"#));
        assert!(doc.contains(
            r#""introspection_endpoint_auth_methods_supported":["private_key_jwt","self_signed_tls_client_auth"]"#
        ));
        let (_, key) = confidential_server();
        let kid = key.public.thumbprint();
        let jwks = format!(r#"{{"keys":[{{"kid":"{kid}",{}]}}"#, &key.public.canonical_json()[1..]);
        let ok = srv
            .register_client(&DynamicClientRequest {
                redirect_uris: vec!["https://dyn.example/cb".into()],
                client_name: None,
                token_endpoint_auth_method: Some("private_key_jwt".into()),
                jwks: Some(jwks.clone()),
                require_signed_request_object: false,
            })
            .unwrap();
        assert_eq!(ok.token_endpoint_auth_method, "private_key_jwt");
        assert_eq!(
            srv.register_client(&DynamicClientRequest {
                redirect_uris: vec!["https://dyn.example/cb".into()],
                client_name: None,
                token_endpoint_auth_method: None,
                jwks: Some(jwks),
                require_signed_request_object: false,
            }),
            Err(OAuthError::InvalidRequest)
        );
    }

    #[test]
    fn admin_resource_server_rules() {
        let mut cfg = ServerConfig::new("https://auth.example", "api");
        cfg.admin_token = DEMO_ADMIN_TOKEN.into();
        let srv = AuthorizationServer::new(cfg, Vec::new(), generate_signing_key(Alg::EdDSA).unwrap());
        let (_, key) = confidential_server();
        let jwks = format!(
            r#"{{"keys":[{{"kid":"{}",{}]}}"#,
            key.public.thumbprint(),
            &key.public.canonical_json()[1..]
        );
        let admin = Some(DEMO_ADMIN_TOKEN);
        // A resource server needs keys, but no redirect URIs.
        assert_eq!(
            srv.create_client(admin, Client { resource_server: true, ..Client::new("rs0", Vec::new()) }),
            Err(AdminError::InvalidRequest)
        );
        assert!(srv
            .create_client(
                admin,
                Client { resource_server: true, ..Client::private_key_jwt("rs", Vec::new(), jwks.clone()) },
            )
            .is_ok());
        // Ordinary clients still need a redirect URI.
        assert_eq!(
            srv.create_client(admin, Client::private_key_jwt("c", Vec::new(), jwks)),
            Err(AdminError::InvalidRequest)
        );
    }
}
