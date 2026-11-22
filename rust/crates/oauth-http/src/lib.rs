//! Axum HTTP surface for authcraft M1 OAuth (ADR 0005).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use jose::alg::Alg;
use jose::signing::{generate_signing_key, SigningKey};
use oauth::{
    AuthorizationServer, AuthorizeRequest, Client, OAuthError, PendingAuthorization, ServerConfig,
    TokenRequest,
};
use serde::Deserialize;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub server: Arc<AuthorizationServer>,
    pending: Arc<Mutex<HashMap<String, PendingAuthorization>>>,
}

impl AppState {
    pub fn new(config: ServerConfig, clients: Vec<Client>, signing: SigningKey) -> Self {
        Self {
            server: Arc::new(AuthorizationServer::new(config, clients, signing)),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn demo() -> Self {
        let key = generate_signing_key(Alg::EdDSA).expect("generate EdDSA key");
        Self::new(
            ServerConfig::new("http://127.0.0.1:8089", "api"),
            vec![Client {
                client_id: "spa".into(),
                redirect_uris: vec![
                    "http://127.0.0.1:9999/cb".into(),
                    "https://app.example/cb".into(),
                ],
            }],
            key,
        )
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/authorize", get(authorize))
        .route("/login", get(login_get).post(login_post))
        .route("/token", post(token))
        .with_state(state)
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
}

async fn authorize(
    State(state): State<AppState>,
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
    };

    match state.server.begin_authorize(&req) {
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
                HeaderValue::from_str(&format!("authcraft_login={ticket}; Path=/; HttpOnly; SameSite=Lax"))
                    .expect("cookie header"),
            );
            (headers, Redirect::to("/login")).into_response()
        }
        Err(err) => {
            // Before a validated redirect_uri, do not redirect.
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": err.code(),
                })),
            )
                .into_response()
        }
    }
}

async fn login_get() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html><head><title>authcraft login</title></head>
<body>
  <h1>Stub login</h1>
  <p>Educational stub — no password (ADR 0005).</p>
  <form method="post" action="/login">
    <label>Subject <input name="subject" value="alice" /></label>
    <button type="submit">Continue</button>
  </form>
</body></html>"#,
    )
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub subject: String,
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

async fn login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(ticket) = cookie_ticket(&headers) else {
        return (StatusCode::BAD_REQUEST, "missing login ticket").into_response();
    };
    let pending = {
        let mut map = state.pending.lock().expect("pending lock");
        map.remove(&ticket)
    };
    let Some(pending) = pending else {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    };

    match state
        .server
        .finish_authorize(pending, form.subject.trim(), now_unix())
    {
        Ok(success) => {
            let mut url = url::Url::parse(&success.redirect_uri).expect("validated redirect_uri");
            {
                let mut q = url.query_pairs_mut();
                q.append_pair("code", &success.code);
                if let Some(state_param) = &success.state {
                    q.append_pair("state", state_param);
                }
            }
            Redirect::to(url.as_str()).into_response()
        }
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
}

async fn token(State(state): State<AppState>, Form(form): Form<TokenForm>) -> Response {
    let req = TokenRequest {
        grant_type: form.grant_type.unwrap_or_default(),
        code: form.code.unwrap_or_default(),
        redirect_uri: form.redirect_uri.unwrap_or_default(),
        client_id: form.client_id.unwrap_or_default(),
        code_verifier: form.code_verifier.unwrap_or_default(),
    };
    match state.server.exchange_token(&req, now_unix()) {
        Ok(tok) => Json(serde_json::json!({
            "access_token": tok.access_token,
            "token_type": tok.token_type,
            "expires_in": tok.expires_in,
        }))
        .into_response(),
        Err(err) => token_error(err),
    }
}

fn token_error(err: OAuthError) -> Response {
    let status = match err {
        OAuthError::InvalidRequest | OAuthError::UnsupportedGrantType => StatusCode::BAD_REQUEST,
        OAuthError::UnauthorizedClient => StatusCode::UNAUTHORIZED,
        OAuthError::InvalidGrant => StatusCode::BAD_REQUEST,
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
        state.server.jwks_document(),
    )
        .into_response()
}
