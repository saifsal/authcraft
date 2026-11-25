//! Axum HTTP surface for authcraft OAuth + OIDC + authn + federation (ADR 0005–0012).

#![forbid(unsafe_code)]

pub mod accounts;
pub mod config;
pub mod mailer;
pub mod pages;
pub mod ratelimit;
pub mod store;
pub mod tls;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State};
use axum::Extension;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use jose::alg::Alg;
use jose::signing::{generate_signing_key, SigningKey};
use oauth::{
    AuthorizationServer, AuthorizeRequest, Client, ClientCredentials, ClientPolicy, DirectoryBind, DynamicClientRequest,
    LoginSubject, OAuthError, OidcRpConfig, PendingAuthorization, ServerConfig, TokenRequest,
    TokenEndpointAuth, TokenTypeHint, DEMO_ADMIN_TOKEN,
};
use serde::Deserialize;

/// Password accepted; waiting for second factor before `finish_authorize`.
#[derive(Debug, Clone)]
struct MfaPending {
    username: String,
    login: LoginSubject,
}

/// In-flight OIDC RP login (outbound authorize).
#[derive(Debug, Clone)]
struct OidcPending {
    ticket: String,
    code_verifier: String,
    nonce: String,
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub server: Arc<AuthorizationServer>,
    pending: Arc<Mutex<HashMap<String, PendingAuthorization>>>,
    mfa_pending: Arc<Mutex<HashMap<String, MfaPending>>>,
    pub oidc_rp: Option<OidcRpConfig>,
    oidc_pending: Arc<Mutex<HashMap<String, OidcPending>>>,
    /// Optional LDAP-style directory (in-memory for demos/tests).
    pub directory: Option<Arc<dyn DirectoryBind>>,
    http: reqwest::Client,
    /// Mark cookies `Secure` even on plain HTTP, for a TLS-terminating
    /// reverse proxy in front (ADR 0023).
    pub secure_cookies: bool,
    /// Sign-up, verification, reset, and login throttling (ADR 0025).
    pub accounts: accounts::Accounts,
    /// Demo mode: show the published demo credentials on the login page.
    pub demo: bool,
}

impl AppState {
    pub fn new(config: ServerConfig, clients: Vec<Client>, signing: SigningKey) -> Self {
        let issuer = config.issuer.clone();
        let server = Arc::new(AuthorizationServer::new(config, clients, signing));
        // Link tokens and the outbox; production swaps in the on-disk database.
        let db = store::open_db(std::path::Path::new(":memory:")).expect("in-memory database");
        Self {
            accounts: accounts::Accounts::new(server.clone(), db, &issuer),
            demo: false,
            server,
            pending: Arc::new(Mutex::new(HashMap::new())),
            mfa_pending: Arc::new(Mutex::new(HashMap::new())),
            oidc_rp: None,
            oidc_pending: Arc::new(Mutex::new(HashMap::new())),
            directory: None,
            http: reqwest::Client::new(),
            secure_cookies: false,
        }
    }

    /// Production state (ADR 0023): no demo user, no demo admin token, no
    /// open registration. `clients` come from configuration and are checked
    /// with `AuthorizationServer::client_is_valid`.
    pub fn production(
        mut config: ServerConfig,
        clients: Vec<Client>,
        signing: SigningKey,
    ) -> Result<Self, config::ConfigError> {
        config.dynamic_registration = false;
        if config.admin_token == DEMO_ADMIN_TOKEN {
            return Err("refusing to run production with the published demo admin token".into());
        }
        let state = Self::new(config, Vec::new(), signing);
        for client in clients {
            if !state.server.client_is_valid(&client) {
                return Err(format!("client {}: invalid configuration", client.client_id).into());
            }
            state.server.add_client(client);
        }
        Ok(state)
    }

    pub fn with_oidc_rp(mut self, cfg: OidcRpConfig) -> Self {
        self.oidc_rp = Some(cfg);
        self
    }

    pub fn with_directory(mut self, directory: Arc<dyn DirectoryBind>) -> Self {
        self.directory = Some(directory);
        self
    }

    pub fn demo() -> Self {
        Self::demo_with_issuer("http://localhost:8089")
    }

    /// Demo state with a chosen issuer (e.g. `https://localhost:8089` under TLS).
    pub fn demo_with_issuer(issuer: &str) -> Self {
        Self::demo_tls(issuer, Vec::new())
    }

    /// Demo state for HTTPS: `tls_client_cas` are the DER CA certificates
    /// trusted for `tls_client_auth` (ADR 0019).
    pub fn demo_tls(issuer: &str, tls_client_cas: Vec<Vec<u8>>) -> Self {
        let key = generate_signing_key(Alg::EdDSA).expect("generate EdDSA key");
        let mut config = ServerConfig::new(issuer, "api");
        config.tls_client_auth_trust_anchors = tls_client_cas;
        config.admin_token = DEMO_ADMIN_TOKEN.into();
        let state = Self::new(
            config,
            vec![Client::new(
                "spa",
                vec![
                    "http://127.0.0.1:9999/cb".into(),
                    "https://app.example/cb".into(),
                ],
            )],
            key,
        );
        state.server.seed_demo_users();
        Self { demo: true, ..state }
    }

    /// Uses `db` for account storage, link tokens, and the outbox
    /// (production, ADR 0024 / 0025): attaches the account repository and
    /// rebuilds [`accounts::Accounts`] on the same database.
    pub fn with_database(mut self, db: store::Db) -> Result<Self, config::ConfigError> {
        let repo = Arc::new(store::SqliteUserStore::from_db(db.clone()));
        let existing = repo.load_all()?;
        tracing::info!("loaded {} account(s)", existing.len());
        self.server.attach_user_repository(repo, existing)?;
        self.accounts = accounts::Accounts::new(self.server.clone(), db, &self.server.config.issuer);
        Ok(self)
    }
}

/// Response headers required by RFC 9700 and RFC 6749 (ADR 0021):
/// - every response: `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`
///   (clickjacking, RFC 9700 §4.16), `Referrer-Policy: no-referrer`
///   (Referer leakage of codes and state, RFC 9700 §4.2.4);
/// - responses that carry tokens, credentials, or user data:
///   `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 §5.1).
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let sensitive = matches!(
        req.uri().path(),
        "/token" | "/par" | "/register" | "/introspect" | "/revoke" | "/userinfo"
    );
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if sensitive {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    res
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/.well-known/jwks.json", get(jwks))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/authorize", get(authorize))
        .route("/par", post(par))
        .route("/register", post(register_client))
        .route("/login", get(login_get).post(login_post))
        .route("/login/oidc/start", get(oidc_start))
        .route("/login/oidc/callback", get(oidc_callback))
        .route("/login/ldap", post(ldap_login))
        .route("/login/mfa", get(mfa_get).post(mfa_post))
        .route("/login/mfa/webauthn/start", post(mfa_webauthn_start))
        .route("/login/mfa/webauthn/finish", post(mfa_webauthn_finish))
        .route("/enroll/totp", post(enroll_totp))
        .route("/enroll/webauthn/start", post(enroll_webauthn_start))
        .route("/enroll/webauthn/finish", post(enroll_webauthn_finish))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/revoke", post(revoke))
        .route("/introspect", post(introspect))
        .route("/admin/clients", get(admin_list_clients).post(admin_create_client))
        .route("/admin/clients/{client_id}", axum::routing::delete(admin_delete_client))
        .route("/admin/users", get(admin_list_users))
        .route("/scim/v2/Users", get(scim_list_users).post(scim_create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(scim_get_user)
                .put(scim_replace_user)
                .delete(scim_delete_user),
        )
        .merge(accounts::routes())
        .with_state(state)
        .layer(axum::middleware::from_fn(security_headers))
}

fn scim_error(status: StatusCode, detail: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/scim+json")],
        oauth::scim::error_json(status.as_u16(), detail),
    )
        .into_response()
}

fn scim_ok(status: StatusCode, body: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/scim+json")],
        body,
    )
        .into_response()
}

async fn scim_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    match state
        .server
        .scim_create_user(admin_bearer(&headers), &body)
    {
        Ok(user) => scim_ok(StatusCode::CREATED, user.to_json()),
        Err(oauth::AdminError::Unauthorized) => scim_error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(oauth::AdminError::Conflict) => scim_error(StatusCode::CONFLICT, "userName exists"),
        Err(oauth::AdminError::InvalidRequest) => {
            scim_error(StatusCode::BAD_REQUEST, "invalid user")
        }
        Err(err) => scim_error(StatusCode::BAD_REQUEST, err.code()),
    }
}

#[derive(Debug, Deserialize)]
pub struct ScimListQuery {
    pub filter: Option<String>,
}

async fn scim_list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ScimListQuery>,
) -> Response {
    match state
        .server
        .scim_list_users(admin_bearer(&headers), q.filter.as_deref())
    {
        Ok(users) => scim_ok(StatusCode::OK, oauth::scim::list_response_json(&users)),
        Err(oauth::AdminError::Unauthorized) => scim_error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(err) => scim_error(StatusCode::BAD_REQUEST, err.code()),
    }
}

async fn scim_get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    match state.server.scim_get_user(admin_bearer(&headers), &id) {
        Ok(user) => scim_ok(StatusCode::OK, user.to_json()),
        Err(oauth::AdminError::Unauthorized) => scim_error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(oauth::AdminError::NotFound) => scim_error(StatusCode::NOT_FOUND, "user not found"),
        Err(err) => scim_error(StatusCode::BAD_REQUEST, err.code()),
    }
}

async fn scim_replace_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Response {
    match state
        .server
        .scim_replace_user(admin_bearer(&headers), &id, &body)
    {
        Ok(user) => scim_ok(StatusCode::OK, user.to_json()),
        Err(oauth::AdminError::Unauthorized) => scim_error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(oauth::AdminError::NotFound) => scim_error(StatusCode::NOT_FOUND, "user not found"),
        Err(oauth::AdminError::Conflict) => scim_error(StatusCode::CONFLICT, "userName exists"),
        Err(err) => scim_error(StatusCode::BAD_REQUEST, err.code()),
    }
}

async fn scim_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    match state.server.scim_delete_user(admin_bearer(&headers), &id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(oauth::AdminError::Unauthorized) => scim_error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(oauth::AdminError::NotFound) => scim_error(StatusCode::NOT_FOUND, "user not found"),
        Err(err) => scim_error(StatusCode::BAD_REQUEST, err.code()),
    }
}

fn admin_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

fn admin_unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

async fn admin_list_clients(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match state.server.list_clients(admin_bearer(&headers)) {
        Ok(clients) => {
            let body: Vec<_> = clients
                .into_iter()
                .map(|c| client_json(&c))
                .collect();
            Json(body).into_response()
        }
        Err(oauth::AdminError::Unauthorized) => admin_unauthorized(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

/// DER bytes of the TLS client leaf certificate for this connection, inserted
/// as a request extension by [`serve_tls`] (ADR 0017). Absent on plain HTTP,
/// so a request header can never supply it.
#[derive(Debug, Clone, Default)]
pub struct TlsClientCert(pub Option<Vec<u8>>);

/// Marker extension: the request arrived over HTTPS ([`serve_tls`]).
#[derive(Debug, Clone, Copy)]
pub struct Https;

fn tls_cert(ext: &Option<Extension<TlsClientCert>>) -> Option<Vec<u8>> {
    ext.as_ref().and_then(|Extension(c)| c.0.clone())
}

#[derive(Debug, Deserialize)]
pub struct AdminCreateClientBody {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    /// `none` (default) or `private_key_jwt` (ADR 0014).
    pub token_endpoint_auth_method: Option<String>,
    /// Public JWKS object; required for `private_key_jwt`.
    pub jwks: Option<serde_json::Value>,
    /// RFC 9101 §10.5 (ADR 0015 B2).
    #[serde(default)]
    pub require_signed_request_object: bool,
    /// May introspect any token (ADR 0016); requires `private_key_jwt`.
    #[serde(default)]
    pub resource_server: bool,
    #[serde(flatten)]
    pub policy: PolicyBody,
    #[serde(flatten)]
    pub tls_subject: TlsSubjectBody,
}

/// RFC 8705 §2.1.2 `tls_client_auth` subject metadata (ADR 0019).
#[derive(Debug, Default, Deserialize)]
pub struct TlsSubjectBody {
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_san_dns: Option<String>,
    pub tls_client_auth_san_uri: Option<String>,
    pub tls_client_auth_san_ip: Option<String>,
    pub tls_client_auth_san_email: Option<String>,
}

impl TlsSubjectBody {
    fn subject(&self) -> Result<Option<oauth::mtls::TlsClientAuthSubject>, OAuthError> {
        oauth::mtls::TlsClientAuthSubject::from_metadata(
            self.tls_client_auth_subject_dn.as_deref(),
            self.tls_client_auth_san_dns.as_deref(),
            self.tls_client_auth_san_uri.as_deref(),
            self.tls_client_auth_san_ip.as_deref(),
            self.tls_client_auth_san_email.as_deref(),
        )
    }
}

/// RFC 9126 / RFC 9449 / RFC 8705 client metadata flags (ADR 0018).
#[derive(Debug, Default, Deserialize)]
pub struct PolicyBody {
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
}

impl From<&PolicyBody> for ClientPolicy {
    fn from(b: &PolicyBody) -> Self {
        ClientPolicy {
            require_pushed_authorization_requests: b.require_pushed_authorization_requests,
            dpop_bound_access_tokens: b.dpop_bound_access_tokens,
            tls_client_certificate_bound_access_tokens: b
                .tls_client_certificate_bound_access_tokens,
        }
    }
}

/// Admin API view of a client (no key material).
fn client_json(c: &Client) -> serde_json::Value {
    let mut body = serde_json::json!({
        "client_id": c.client_id,
        "redirect_uris": c.redirect_uris,
        "client_name": c.client_name,
        "token_endpoint_auth_method": c.token_endpoint_auth.method(),
        "require_signed_request_object": c.require_signed_request_object,
        "resource_server": c.resource_server,
    });
    policy_json(&mut body, &c.policy);
    body
}

/// Echoes a client's policy flags into a JSON response body.
fn policy_json(body: &mut serde_json::Value, p: &ClientPolicy) {
    body["require_pushed_authorization_requests"] = p.require_pushed_authorization_requests.into();
    body["dpop_bound_access_tokens"] = p.dpop_bound_access_tokens.into();
    body["tls_client_certificate_bound_access_tokens"] =
        p.tls_client_certificate_bound_access_tokens.into();
}

/// Maps RFC 7591 `token_endpoint_auth_method`, `jwks`, and the RFC 8705
/// subject metadata to the client model. `None` means inconsistent metadata.
fn client_auth_from_body(
    method: Option<&str>,
    jwks: Option<&serde_json::Value>,
    tls_subject: &TlsSubjectBody,
) -> Option<TokenEndpointAuth> {
    let subject = tls_subject.subject().ok()?;
    if subject.is_some() != (method == Some("tls_client_auth")) {
        return None;
    }
    match (method, jwks) {
        (None | Some("none"), None) => Some(TokenEndpointAuth::None),
        (Some("tls_client_auth"), None) => {
            subject.map(|subject| TokenEndpointAuth::TlsClientAuth { subject })
        }
        (Some("private_key_jwt"), Some(jwks)) => Some(TokenEndpointAuth::PrivateKeyJwt {
            jwks: jwks.to_string(),
        }),
        (Some("self_signed_tls_client_auth"), Some(jwks)) => {
            oauth::mtls::thumbprints_from_jwks(&jwks.to_string())
                .ok()
                .map(|cert_thumbprints| TokenEndpointAuth::SelfSignedTlsClientAuth { cert_thumbprints })
        }
        _ => None,
    }
}

async fn admin_create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AdminCreateClientBody>,
) -> Response {
    let Some(token_endpoint_auth) =
        client_auth_from_body(
        body.token_endpoint_auth_method.as_deref(),
        body.jwks.as_ref(),
        &body.tls_subject,
    )
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_request" })),
        )
            .into_response();
    };
    let client = Client {
        client_id: body.client_id,
        redirect_uris: body.redirect_uris,
        client_name: body.client_name,
        token_endpoint_auth,
        require_signed_request_object: body.require_signed_request_object,
        resource_server: body.resource_server,
        policy: (&body.policy).into(),
    };
    match state.server.create_client(admin_bearer(&headers), client) {
        Ok(c) => (StatusCode::CREATED, Json(client_json(&c))).into_response(),
        Err(oauth::AdminError::Unauthorized) => admin_unauthorized(),
        Err(oauth::AdminError::Conflict) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "conflict" })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

async fn admin_delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(client_id): axum::extract::Path<String>,
) -> Response {
    match state
        .server
        .delete_client(admin_bearer(&headers), &client_id)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(oauth::AdminError::Unauthorized) => admin_unauthorized(),
        Err(oauth::AdminError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not_found" })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

async fn admin_list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match state.server.list_users(admin_bearer(&headers)) {
        Ok(users) => {
            let body: Vec<_> = users
                .into_iter()
                .map(|u| {
                    serde_json::json!({
                        "username": u.username,
                        "subject": u.subject,
                        "name": u.name,
                        "email": u.email,
                        "totp_enrolled": u.totp_enrolled,
                        "webauthn_enrolled": u.webauthn_enrolled,
                    })
                })
                .collect();
            Json(body).into_response()
        }
        Err(oauth::AdminError::Unauthorized) => admin_unauthorized(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_ticket() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).expect("rng");
    jose::b64url::encode(&bytes)
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub request_uri: Option<String>,
    /// RFC 9101 request object (ADR 0015).
    pub request: Option<String>,
}

async fn authorize(
    State(state): State<AppState>,
    https: Option<Extension<Https>>,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let req = AuthorizeRequest {
        response_type: q.response_type.unwrap_or_default(),
        client_id: q.client_id.unwrap_or_default(),
        redirect_uri: q.redirect_uri.unwrap_or_default(),
        code_challenge: q.code_challenge.unwrap_or_default(),
        code_challenge_method: q.code_challenge_method.unwrap_or_default(),
        state: q.state,
        scope: q.scope,
        nonce: q.nonce,
        request_uri: q.request_uri,
        request: q.request,
    };

    match state.server.begin_authorize(&req, now_unix()) {
        Ok(pending) => {
            let ticket = random_ticket();
            state
                .pending
                .lock()
                .expect("pending lock")
                .insert(ticket.clone(), pending);
            let mut headers = HeaderMap::new();
            headers.insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&format!(
                    "authcraft_login={ticket}; Path=/; HttpOnly; SameSite=Lax{}",
                    // RFC 6265 §4.1.2.5: never send the ticket over plain HTTP
                    // once the AS is served over HTTPS (ADR 0021).
                    if https.is_some() || state.secure_cookies { "; Secure" } else { "" }
                ))
                .expect("cookie header"),
            );
            (headers, Redirect::to("/login")).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": err.code(),
            })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct ParForm {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    /// RFC 9101 request object (ADR 0015).
    pub request: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterClientBody {
    pub redirect_uris: Option<Vec<String>>,
    pub client_name: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    /// Inline public JWKS object for `private_key_jwt` (ADR 0014).
    pub jwks: Option<serde_json::Value>,
    /// RFC 9101 §10.5 (ADR 0015 B2).
    #[serde(default)]
    pub require_signed_request_object: bool,
    #[serde(flatten)]
    pub policy: PolicyBody,
    #[serde(flatten)]
    pub tls_subject: TlsSubjectBody,
}

async fn register_client(
    State(state): State<AppState>,
    Json(body): Json<RegisterClientBody>,
) -> Response {
    // Production servers configure clients instead (ADR 0023); discovery
    // omits `registration_endpoint` too.
    if !state.server.config.dynamic_registration {
        return StatusCode::NOT_FOUND.into_response();
    }
    let req = DynamicClientRequest {
        redirect_uris: body.redirect_uris.unwrap_or_default(),
        client_name: body.client_name,
        token_endpoint_auth_method: body.token_endpoint_auth_method,
        jwks: body.jwks.map(|v| v.to_string()),
        require_signed_request_object: body.require_signed_request_object,
        policy: (&body.policy).into(),
        tls_client_auth_subject: match body.tls_subject.subject() {
            Ok(s) => s,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": err.code() })),
                )
                    .into_response()
            }
        },
    };
    match state.server.register_client(&req) {
        Ok(ok) => {
            let mut body = serde_json::json!({
                "client_id": ok.client_id,
                "redirect_uris": ok.redirect_uris,
                "client_name": ok.client_name,
                "token_endpoint_auth_method": ok.token_endpoint_auth_method,
                "require_signed_request_object": ok.require_signed_request_object,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            });
            policy_json(&mut body, &ok.policy);
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

async fn par(
    State(state): State<AppState>,
    cert: Option<Extension<TlsClientCert>>,
    Form(form): Form<ParForm>,
) -> Response {
    let req = AuthorizeRequest {
        response_type: form.response_type.unwrap_or_default(),
        client_id: form.client_id.unwrap_or_default(),
        redirect_uri: form.redirect_uri.unwrap_or_default(),
        code_challenge: form.code_challenge.unwrap_or_default(),
        code_challenge_method: form.code_challenge_method.unwrap_or_default(),
        state: form.state,
        scope: form.scope,
        nonce: form.nonce,
        request_uri: None,
        request: form.request,
    };
    let client_auth = ClientCredentials {
        client_assertion_type: form.client_assertion_type,
        client_assertion: form.client_assertion,
        tls_client_cert: tls_cert(&cert),
    };
    match state.server.push_authorization(&req, &client_auth, now_unix()) {
        Ok(ok) => Json(serde_json::json!({
            "request_uri": ok.request_uri,
            "expires_in": ok.expires_in,
        }))
        .into_response(),
        Err(err @ (OAuthError::InvalidClient | OAuthError::UnauthorizedClient)) => {
            token_error(err)
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

/// The sign-in page (ADR 0025). Demo credentials are shown only in demo mode.
fn login_page(state: &AppState, error: Option<&str>, username: &str) -> Html<String> {
    let demo = if state.demo {
        r#"<p class="muted">Demo server: sign in as <code>alice</code> / <code>password</code>.</p>"#
    } else {
        ""
    };
    let oidc = if state.oidc_rp.is_some() {
        r#"<p><a href="/login/oidc/start">Sign in with the upstream OpenID provider</a></p>"#
    } else {
        ""
    };
    let ldap = if state.directory.is_some() {
        r#"<h2>Directory (LDAP gateway)</h2>
<form method="post" action="/login/ldap">
  <label for="ldap-user">Username</label><input id="ldap-user" name="username">
  <label for="ldap-pass">Password</label><input id="ldap-pass" name="password" type="password">
  <button type="submit">Sign in via directory</button>
</form>"#
    } else {
        ""
    };
    let username = if username.is_empty() && state.demo { "alice" } else { username };
    let body = format!(
        r#"<h1>Sign in</h1>
<p class="lead">Use your authcraft account to continue.</p>
{demo}
{err}
<form method="post" action="/login">
  <label for="username">Email</label>
  <input id="username" name="username" autocomplete="username" required value="{username}">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
<div class="links"><a href="/signup">Create an account</a><a href="/forgot">Forgot password?</a></div>
{oidc}
{ldap}"#,
        err = pages::error_line(error),
        username = pages::esc(username),
    );
    pages::layout("Sign in", &body)
}

async fn login_get(State(state): State<AppState>) -> Html<String> {
    login_page(&state, None, "")
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

fn cookie_ticket(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("authcraft_login=") {
            return Some(v.to_owned());
        }
    }
    None
}

fn redirect_with_code(success: &oauth::AuthorizationSuccess) -> Response {
    let mut url = url::Url::parse(&success.redirect_uri).expect("validated redirect_uri");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("code", &success.code);
        if let Some(state_param) = &success.state {
            q.append_pair("state", state_param);
        }
        // RFC 9207 mix-up mitigation.
        q.append_pair("iss", &success.iss);
    }
    Redirect::to(url.as_str()).into_response()
}

async fn oidc_start(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(cfg) = state.oidc_rp.as_ref() else {
        return (StatusCode::NOT_FOUND, "OIDC RP not configured").into_response();
    };
    let Some(ticket) = cookie_ticket(&headers) else {
        return (StatusCode::BAD_REQUEST, "missing login ticket").into_response();
    };
    if !state
        .pending
        .lock()
        .expect("pending lock")
        .contains_key(&ticket)
    {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    }

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        cfg.issuer.trim_end_matches('/')
    );
    let disc: serde_json::Value = match state.http.get(&discovery_url).send().await {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(_) => {
                return (StatusCode::BAD_GATEWAY, "upstream discovery failed").into_response();
            }
        },
        Err(_) => return (StatusCode::BAD_GATEWAY, "upstream discovery failed").into_response(),
    };
    let Some(authz_ep) = disc.get("authorization_endpoint").and_then(|v| v.as_str()) else {
        return (StatusCode::BAD_GATEWAY, "upstream missing authorization_endpoint")
            .into_response();
    };

    let start = match oauth::start_oidc_login(cfg, authz_ep) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "oidc start failed").into_response(),
    };
    state.oidc_pending.lock().expect("oidc lock").insert(
        start.state.clone(),
        OidcPending {
            ticket,
            code_verifier: start.code_verifier,
            nonce: start.nonce,
        },
    );
    Redirect::to(&start.authorize_url).into_response()
}

#[derive(Debug, Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

async fn oidc_callback(
    State(state): State<AppState>,
    Query(q): Query<OidcCallbackQuery>,
) -> Response {
    let Some(cfg) = state.oidc_rp.clone() else {
        return (StatusCode::NOT_FOUND, "OIDC RP not configured").into_response();
    };
    if q.error.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            login_page(&state, Some("Upstream login failed"), ""),
        )
            .into_response();
    }
    let (Some(code), Some(state_param)) = (q.code.as_deref(), q.state.as_deref()) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    let pending_oidc = {
        let mut map = state.oidc_pending.lock().expect("oidc lock");
        map.remove(state_param)
    };
    let Some(pending_oidc) = pending_oidc else {
        return (StatusCode::BAD_REQUEST, "unknown oidc state").into_response();
    };

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        cfg.issuer.trim_end_matches('/')
    );
    let disc: serde_json::Value = match state.http.get(&discovery_url).send().await {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(_) => {
                return (StatusCode::BAD_GATEWAY, "upstream discovery failed").into_response();
            }
        },
        Err(_) => return (StatusCode::BAD_GATEWAY, "upstream discovery failed").into_response(),
    };
    let Some(token_ep) = disc.get("token_endpoint").and_then(|v| v.as_str()) else {
        return (StatusCode::BAD_GATEWAY, "upstream missing token_endpoint").into_response();
    };
    let Some(jwks_uri) = disc.get("jwks_uri").and_then(|v| v.as_str()) else {
        return (StatusCode::BAD_GATEWAY, "upstream missing jwks_uri").into_response();
    };

    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("redirect_uri", cfg.redirect_uri.clone()),
        ("client_id", cfg.client_id.clone()),
        ("code_verifier", pending_oidc.code_verifier.clone()),
    ];
    if let Some(secret) = &cfg.client_secret {
        form.push(("client_secret", secret.clone()));
    }
    let token_body = match state.http.post(token_ep).form(&form).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(_) => return (StatusCode::BAD_GATEWAY, "token response unreadable").into_response(),
        },
        Err(_) => return (StatusCode::BAD_GATEWAY, "token request failed").into_response(),
    };
    let id_token = match oauth::id_token_from_token_response(&token_body) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                login_page(&state, Some("Upstream token missing id_token"), ""),
            )
                .into_response();
        }
    };

    let jwks_body = match state.http.get(jwks_uri).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(_) => return (StatusCode::BAD_GATEWAY, "jwks unreadable").into_response(),
        },
        Err(_) => return (StatusCode::BAD_GATEWAY, "jwks fetch failed").into_response(),
    };
    let jwks = match jose::jwks::Jwks::parse(jwks_body.as_bytes()) {
        Ok(j) => j,
        Err(_) => return (StatusCode::BAD_GATEWAY, "jwks parse failed").into_response(),
    };

    let login = match oauth::login_subject_from_id_token(
        &id_token,
        &jwks,
        &cfg,
        &pending_oidc.nonce,
        now_unix(),
    ) {
        Ok(l) => l,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                login_page(&state, Some("Invalid upstream ID token"), ""),
            )
                .into_response();
        }
    };

    let pending = {
        let mut map = state.pending.lock().expect("pending lock");
        map.remove(&pending_oidc.ticket)
    };
    let Some(pending) = pending else {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    };

    match state.server.finish_authorize(pending, &login, now_unix()) {
        Ok(success) => redirect_with_code(&success),
        Err(err) => (StatusCode::BAD_REQUEST, err.code()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct LdapLoginForm {
    pub username: String,
    pub password: String,
}

async fn ldap_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LdapLoginForm>,
) -> Response {
    let Some(directory) = state.directory.as_ref() else {
        return (StatusCode::NOT_FOUND, "directory not configured").into_response();
    };
    let Some(ticket) = cookie_ticket(&headers) else {
        return (StatusCode::BAD_REQUEST, "missing login ticket").into_response();
    };
    let pending = {
        let map = state.pending.lock().expect("pending lock");
        map.get(&ticket).cloned()
    };
    let Some(pending) = pending else {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    };

    let login = match directory.authenticate(form.username.trim(), &form.password) {
        Ok(login) => login,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                login_page(&state, Some("Invalid directory credentials"), ""),
            )
                .into_response();
        }
    };

    {
        let mut map = state.pending.lock().expect("pending lock");
        map.remove(&ticket);
    }

    match state.server.finish_authorize(pending, &login, now_unix()) {
        Ok(success) => redirect_with_code(&success),
        Err(err) => (StatusCode::BAD_REQUEST, err.code()).into_response(),
    }
}

async fn login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(ticket) = cookie_ticket(&headers) else {
        return (StatusCode::BAD_REQUEST, "missing login ticket").into_response();
    };
    let has_pending = {
        let map = state.pending.lock().expect("pending lock");
        map.contains_key(&ticket)
    };
    if !has_pending {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    }

    // ADR 0025: login names are lowercased emails (the demo user is `alice`).
    let username = form.username.trim().to_ascii_lowercase();
    let client = ratelimit::client_key(&headers);
    if !state.accounts.login_allowed(&username, &client) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            login_page(&state, Some("Too many attempts. Try again later."), &username),
        )
            .into_response();
    }
    // Argon2id is slow by design; keep it off the async workers.
    let server = state.server.clone();
    let (name, password) = (username.clone(), form.password);
    let result = tokio::task::spawn_blocking(move || server.authenticate_password(&name, &password))
        .await
        .unwrap_or(Err(oauth::AuthnError::StorageUnavailable));
    let login = match result {
        Ok(login) => {
            state.accounts.login_succeeded(&username);
            login
        }
        Err(err) => {
            let message = match err {
                oauth::AuthnError::EmailNotVerified => {
                    // The password was right: send a fresh link, as glossa does.
                    let _ = state.accounts.resend_verification(&username, &client);
                    "Confirm your email address first. We have sent a new confirmation link."
                }
                oauth::AuthnError::StorageUnavailable => "Temporarily unavailable; try again.",
                _ => {
                    state.accounts.login_failed(&username);
                    "Invalid email or password."
                }
            };
            return (
                StatusCode::UNAUTHORIZED,
                login_page(&state, Some(message), &username),
            )
                .into_response();
        }
    };

    if state.server.user_mfa_enrolled(&username) {
        state.mfa_pending.lock().expect("mfa lock").insert(
            ticket,
            MfaPending {
                username,
                login,
            },
        );
        return Redirect::to("/login/mfa").into_response();
    }

    let pending = {
        let mut map = state.pending.lock().expect("pending lock");
        map.remove(&ticket)
    };
    let Some(pending) = pending else {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    };

    match state.server.finish_authorize(pending, &login, now_unix()) {
        Ok(success) => redirect_with_code(&success),
        Err(err) => (StatusCode::BAD_REQUEST, err.code()).into_response(),
    }
}

fn mfa_page(error: Option<&str>) -> Html<String> {
    let err = error
        .map(|e| format!("<p style=\"color:red\">{e}</p>"))
        .unwrap_or_default();
    Html(format!(
        r#"<!doctype html>
<html><head><title>authcraft MFA</title></head>
<body>
  <h1>Two-factor authentication</h1>
  <p>Enter a TOTP code if enrolled, or complete WebAuthn via the JSON MFA endpoints (ADR 0010).</p>
  {err}
  <form method="post" action="/login/mfa">
    <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" /></label>
    <button type="submit">Verify TOTP</button>
  </form>
</body></html>"#
    ))
}

async fn mfa_get() -> Html<String> {
    mfa_page(None)
}

#[derive(Debug, Deserialize)]
pub struct MfaForm {
    pub code: String,
}

async fn mfa_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaForm>,
) -> Response {
    let Some(ticket) = cookie_ticket(&headers) else {
        return (StatusCode::BAD_REQUEST, "missing login ticket").into_response();
    };
    let mfa = {
        let map = state.mfa_pending.lock().expect("mfa lock");
        map.get(&ticket).cloned()
    };
    let Some(mfa) = mfa else {
        return (StatusCode::BAD_REQUEST, "no MFA session").into_response();
    };

    if !state.server.user_totp_enrolled(&mfa.username) {
        return (
            StatusCode::BAD_REQUEST,
            mfa_page(Some("TOTP not enrolled; use WebAuthn MFA endpoints")),
        )
            .into_response();
    }
    match state
        .server
        .verify_totp(&mfa.username, &form.code, now_unix())
    {
        Ok(()) => {}
        Err(oauth::AuthnError::TooManyAttempts) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                mfa_page(Some("Too many attempts; try again later")),
            )
                .into_response();
        }
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, mfa_page(Some("Invalid code"))).into_response();
        }
    }

    state.mfa_pending.lock().expect("mfa lock").remove(&ticket);
    let pending = {
        let mut map = state.pending.lock().expect("pending lock");
        map.remove(&ticket)
    };
    let Some(pending) = pending else {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    };

    match state
        .server
        .finish_authorize(pending, &mfa.login, now_unix())
    {
        Ok(success) => redirect_with_code(&success),
        Err(err) => (StatusCode::BAD_REQUEST, err.code()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct EnrollTotpForm {
    pub username: String,
    pub password: String,
}

async fn enroll_totp(State(state): State<AppState>, Form(form): Form<EnrollTotpForm>) -> Response {
    if state
        .server
        .authenticate_password(form.username.trim(), &form.password)
        .is_err()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_credentials" })),
        )
            .into_response();
    }
    match state
        .server
        .enroll_totp(form.username.trim(), &state.server.config.issuer)
    {
        Ok(enroll) => Json(serde_json::json!({
            "secret": enroll.secret_b32,
            "otpauth_uri": enroll.otpauth_uri,
        }))
        .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct EnrollWebauthnStartForm {
    pub username: String,
    pub password: String,
}

async fn enroll_webauthn_start(
    State(state): State<AppState>,
    Form(form): Form<EnrollWebauthnStartForm>,
) -> Response {
    if state
        .server
        .authenticate_password(form.username.trim(), &form.password)
        .is_err()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_credentials" })),
        )
            .into_response();
    }
    match state.server.webauthn_start_registration(form.username.trim()) {
        Ok(ccr) => Json(ccr).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct EnrollWebauthnFinishBody {
    pub username: String,
    pub credential: serde_json::Value,
}

async fn enroll_webauthn_finish(
    State(state): State<AppState>,
    Json(body): Json<EnrollWebauthnFinishBody>,
) -> Response {
    let reg: webauthn_rs::prelude::RegisterPublicKeyCredential =
        match serde_json::from_value(body.credential) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_mfa" })),
                )
                    .into_response();
            }
        };
    match state
        .server
        .webauthn_finish_registration(body.username.trim(), &reg)
    {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

async fn mfa_webauthn_start(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(ticket) = cookie_ticket(&headers) else {
        return (StatusCode::BAD_REQUEST, "missing login ticket").into_response();
    };
    let username = {
        let map = state.mfa_pending.lock().expect("mfa lock");
        map.get(&ticket).map(|m| m.username.clone())
    };
    let Some(username) = username else {
        return (StatusCode::BAD_REQUEST, "no MFA session").into_response();
    };
    match state
        .server
        .webauthn_start_authentication(&ticket, &username)
    {
        Ok(rcr) => Json(rcr).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

async fn mfa_webauthn_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(credential): Json<serde_json::Value>,
) -> Response {
    let Some(ticket) = cookie_ticket(&headers) else {
        return (StatusCode::BAD_REQUEST, "missing login ticket").into_response();
    };
    let mfa = {
        let map = state.mfa_pending.lock().expect("mfa lock");
        map.get(&ticket).cloned()
    };
    let Some(mfa) = mfa else {
        return (StatusCode::BAD_REQUEST, "no MFA session").into_response();
    };
    let auth: webauthn_rs::prelude::PublicKeyCredential = match serde_json::from_value(credential)
    {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_mfa" })),
            )
                .into_response();
        }
    };
    if state
        .server
        .webauthn_finish_authentication(&ticket, &mfa.username, &auth)
        .is_err()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_mfa" })),
        )
            .into_response();
    }

    state.mfa_pending.lock().expect("mfa lock").remove(&ticket);
    let pending = {
        let mut map = state.pending.lock().expect("pending lock");
        map.remove(&ticket)
    };
    let Some(pending) = pending else {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    };

    match state
        .server
        .finish_authorize(pending, &mfa.login, now_unix())
    {
        Ok(success) => redirect_with_code(&success),
        Err(err) => (StatusCode::BAD_REQUEST, err.code()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

fn dpop_header(headers: &HeaderMap) -> Option<&str> {
    headers.get("dpop")?.to_str().ok()
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    cert: Option<Extension<TlsClientCert>>,
    Form(form): Form<TokenForm>,
) -> Response {
    let req = TokenRequest {
        grant_type: form.grant_type.unwrap_or_default(),
        code: form.code.unwrap_or_default(),
        redirect_uri: form.redirect_uri.unwrap_or_default(),
        client_id: form.client_id.unwrap_or_default(),
        code_verifier: form.code_verifier.unwrap_or_default(),
        refresh_token: form.refresh_token.unwrap_or_default(),
        client_assertion_type: form.client_assertion_type,
        client_assertion: form.client_assertion,
    };
    let htu = format!("{}/token", state.server.config.issuer);
    match state
        .server
        .exchange_token_tls(
            &req,
            now_unix(),
            dpop_header(&headers),
            &htu,
            tls_cert(&cert).as_deref(),
        )
    {
        Ok(tok) => {
            let mut body = serde_json::json!({
                "access_token": tok.access_token,
                "token_type": tok.token_type,
                "expires_in": tok.expires_in,
            });
            if let Some(id_token) = tok.id_token {
                body["id_token"] = serde_json::Value::String(id_token);
            }
            if let Some(refresh_token) = tok.refresh_token {
                body["refresh_token"] = serde_json::Value::String(refresh_token);
            }
            let mut resp = Json(body).into_response();
            if let Some(nonce) = tok.dpop_nonce {
                if let Ok(v) = HeaderValue::from_str(&nonce) {
                    resp.headers_mut().insert("dpop-nonce", v);
                }
            }
            resp
        }
        Err(OAuthError::UseDpopNonce) => {
            let nonce = state.server.dpop_nonce().unwrap_or_default();
            let mut resp = (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "use_dpop_nonce",
                })),
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&nonce) {
                resp.headers_mut().insert("dpop-nonce", v);
            }
            resp
        }
        Err(err) => token_error(err),
    }
}

fn token_error(err: OAuthError) -> Response {
    let status = match err {
        OAuthError::InvalidRequest
        | OAuthError::UnsupportedGrantType
        | OAuthError::InvalidRequestObject => StatusCode::BAD_REQUEST,
        OAuthError::UnauthorizedClient | OAuthError::InvalidClient | OAuthError::InvalidToken => {
            StatusCode::UNAUTHORIZED
        }
        OAuthError::InvalidGrant | OAuthError::UseDpopNonce => StatusCode::BAD_REQUEST,
        OAuthError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({
            "error": err.code(),
        })),
    )
        .into_response()
}

async fn jwks(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.server.jwks_document_at(now_unix()),
    )
        .into_response()
}

async fn openid_configuration(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.server.openid_configuration(),
    )
        .into_response()
}

fn access_token_from_auth(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("DPoP "))
}

async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
    cert: Option<Extension<TlsClientCert>>,
) -> Response {
    let Some(token) = access_token_from_auth(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"Bearer error="invalid_token""#),
            )],
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response();
    };

    let htu = format!("{}/userinfo", state.server.config.issuer);
    match state
        .server
        .userinfo_tls(
            token,
            now_unix(),
            dpop_header(&headers),
            &htu,
            tls_cert(&cert).as_deref(),
        )
    {
        Ok(info) => {
            let mut body = serde_json::json!({ "sub": info.sub });
            if let Some(name) = info.name {
                body["name"] = serde_json::Value::String(name);
            }
            if let Some(email) = info.email {
                body["email"] = serde_json::Value::String(email);
                if let Some(v) = info.email_verified {
                    body["email_verified"] = serde_json::Value::Bool(v);
                }
            }
            Json(body).into_response()
        }
        Err(OAuthError::UseDpopNonce) => {
            let nonce = state.server.dpop_nonce().unwrap_or_default();
            let mut resp = (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "use_dpop_nonce" })),
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&nonce) {
                resp.headers_mut().insert("dpop-nonce", v);
            }
            resp
        }
        Err(err) => (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"Bearer error="invalid_token""#),
            )],
            Json(serde_json::json!({ "error": err.code() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

async fn revoke(
    State(state): State<AppState>,
    cert: Option<Extension<TlsClientCert>>,
    Form(form): Form<RevokeForm>,
) -> Response {
    let client_id = form.client_id.unwrap_or_default();
    let token = form.token.unwrap_or_default();
    let hint = TokenTypeHint::parse(form.token_type_hint.as_deref());
    let client_auth = ClientCredentials {
        client_assertion_type: form.client_assertion_type,
        client_assertion: form.client_assertion,
        tls_client_cert: tls_cert(&cert),
    };
    // RFC 7009 §2.2: 200 once the client is authenticated, whether or not the
    // token was valid; client authentication failures are `invalid_client`.
    match state
        .server
        .revoke(&token, hint, &client_id, &client_auth, now_unix())
    {
        Err(err @ (OAuthError::InvalidClient | OAuthError::UnauthorizedClient)) => {
            token_error(err)
        }
        _ => StatusCode::OK.into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    /// Caller identity; must be a `private_key_jwt` client (ADR 0016).
    pub client_id: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

async fn introspect(
    State(state): State<AppState>,
    cert: Option<Extension<TlsClientCert>>,
    Form(form): Form<IntrospectForm>,
) -> Response {
    let token = form.token.unwrap_or_default();
    let hint = TokenTypeHint::parse(form.token_type_hint.as_deref());
    let caller = form.client_id.unwrap_or_default();
    let client_auth = ClientCredentials {
        client_assertion_type: form.client_assertion_type,
        client_assertion: form.client_assertion,
        tls_client_cert: tls_cert(&cert),
    };
    match state
        .server
        .introspect(&token, hint, &caller, &client_auth, now_unix())
    {
        Ok(info) => {
            let mut body = serde_json::json!({ "active": info.active });
            if info.active {
                if let Some(v) = info.client_id {
                    body["client_id"] = serde_json::Value::String(v);
                }
                if let Some(v) = info.sub {
                    body["sub"] = serde_json::Value::String(v);
                }
                if let Some(v) = info.scope {
                    body["scope"] = serde_json::Value::String(v);
                }
                if let Some(v) = info.exp {
                    body["exp"] = serde_json::json!(v);
                }
                if let Some(v) = info.iat {
                    body["iat"] = serde_json::json!(v);
                }
                if let Some(v) = info.token_type {
                    body["token_type"] = serde_json::Value::String(v.into());
                }
                // RFC 9449 §6.2 / RFC 8705 §3.2: report the token binding.
                let mut cnf = serde_json::Map::new();
                if let Some(v) = info.cnf_jkt {
                    cnf.insert("jkt".into(), serde_json::Value::String(v));
                }
                if let Some(v) = info.cnf_x5t_s256 {
                    cnf.insert("x5t#S256".into(), serde_json::Value::String(v));
                }
                if !cnf.is_empty() {
                    body["cnf"] = serde_json::Value::Object(cnf);
                }
            }
            Json(body).into_response()
        }
        Err(err @ (OAuthError::InvalidClient | OAuthError::UnauthorizedClient)) => {
            token_error(err)
        }
        Err(_) => Json(serde_json::json!({ "active": false })).into_response(),
    }
}
