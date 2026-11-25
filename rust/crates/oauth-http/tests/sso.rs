//! Single sign-on (ADR 0026): a second authorization request reuses the
//! authcraft session; `prompt=login` and `prompt=none`; standalone sign-in to
//! the account page; CSRF-checked logout; password reset ends sessions.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use oauth::pkce;
use oauth_http::{app, AppState};
use tower::ServiceExt;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT: &str = "https://app.example/cb";

struct Resp {
    status: StatusCode,
    location: Option<String>,
    cookies: Vec<String>,
    body: String,
}

impl Resp {
    fn cookie(&self, name: &str) -> Option<String> {
        self.cookies
            .iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .cloned()
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let location = res
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_owned());
    let cookies = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok()?.split(';').next().map(str::to_owned))
        .collect();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        location,
        cookies,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn get(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::empty()).unwrap()
}

fn post(uri: &str, body: String, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::from(body)).unwrap()
}

fn authorize_uri(extra: &str) -> String {
    let challenge = pkce::challenge_s256(VERIFIER).unwrap();
    format!(
        "/authorize?response_type=code&client_id=spa&redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=openid&nonce=n1&state=s1{extra}",
        enc(REDIRECT),
        enc(&challenge)
    )
}

/// Signs alice in through an authorization request; returns the session cookie.
async fn sign_in(app: &Router) -> String {
    let start = send(app, get(&authorize_uri(""), None)).await;
    assert_eq!(start.location.as_deref(), Some("/login"));
    let ticket = start.cookie("authcraft_login").unwrap();
    let done = send(
        app,
        post("/login", "username=alice&password=password".into(), Some(&ticket)),
    )
    .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    assert!(done.location.as_deref().unwrap().starts_with(REDIRECT));
    done.cookie("authcraft_session").expect("session cookie")
}

#[tokio::test]
async fn second_authorization_reuses_the_session() {
    let app = app(AppState::demo());
    let session = sign_in(&app).await;
    let again = send(&app, get(&authorize_uri(""), Some(&session))).await;
    assert_eq!(again.status, StatusCode::SEE_OTHER);
    let location = again.location.unwrap();
    assert!(location.starts_with(REDIRECT), "straight back with a code: {location}");
    assert!(location.contains("code=") && location.contains("state=s1"));
}

#[tokio::test]
async fn prompt_login_forces_a_fresh_sign_in() {
    let app = app(AppState::demo());
    let session = sign_in(&app).await;
    let res = send(&app, get(&authorize_uri("&prompt=login"), Some(&session))).await;
    assert_eq!(res.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn prompt_none_without_session_returns_login_required() {
    let app = app(AppState::demo());
    let res = send(&app, get(&authorize_uri("&prompt=none"), None)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    let location = res.location.unwrap();
    assert!(location.starts_with(REDIRECT), "{location}");
    assert!(location.contains("error=login_required"));
    assert!(location.contains("state=s1"));
    assert!(location.contains("iss="));
    // With a session, prompt=none succeeds silently.
    let session = sign_in(&app).await;
    let ok = send(&app, get(&authorize_uri("&prompt=none"), Some(&session))).await;
    assert!(ok.location.unwrap().contains("code="));
}

#[tokio::test]
async fn standalone_sign_in_lands_on_the_account_page() {
    let app = app(AppState::demo());
    let anon = send(&app, get("/account", None)).await;
    assert_eq!(anon.location.as_deref(), Some("/login?return_to=/account"));

    let page = send(&app, get("/login?return_to=/account", None)).await;
    let ticket = page.cookie("authcraft_login").expect("standalone ticket");
    let done = send(&app, post("/login", "username=alice&password=password".into(), Some(&ticket))).await;
    assert_eq!(done.location.as_deref(), Some("/account"));
    let session = done.cookie("authcraft_session").unwrap();
    let account = send(&app, get("/account", Some(&session))).await;
    assert_eq!(account.status, StatusCode::OK);
    assert!(account.body.contains("alice@example.com"));
}

#[tokio::test]
async fn return_to_must_be_a_local_path() {
    let app = app(AppState::demo());
    for bad in ["https://evil.example/", "//evil.example/", "/\\evil.example"] {
        let page = send(&app, get(&format!("/login?return_to={}", enc(bad)), None)).await;
        let ticket = page.cookie("authcraft_login").unwrap();
        let done = send(&app, post("/login", "username=alice&password=password".into(), Some(&ticket))).await;
        assert_eq!(done.location.as_deref(), Some("/account"), "{bad}");
    }
}

#[tokio::test]
async fn logout_needs_the_csrf_token() {
    let app = app(AppState::demo());
    let session = sign_in(&app).await;
    let forged = send(&app, post("/logout", "csrf=wrong".into(), Some(&session))).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    // Still signed in.
    let still = send(&app, get(&authorize_uri(""), Some(&session))).await;
    assert!(still.location.unwrap().contains("code="));

    let page = send(&app, get("/logout", Some(&session))).await;
    let marker = "name=\"csrf\" value=\"";
    let start = page.body.find(marker).unwrap() + marker.len();
    let csrf = &page.body[start..start + page.body[start..].find('"').unwrap()];
    let out = send(&app, post("/logout", format!("csrf={}", enc(csrf)), Some(&session))).await;
    assert_eq!(out.status, StatusCode::OK);
    let after = send(&app, get(&authorize_uri(""), Some(&session))).await;
    assert_eq!(after.location.as_deref(), Some("/login"), "session ended");
}

#[tokio::test]
async fn password_reset_ends_sessions() {
    let state = AppState::demo();
    let app = app(state.clone());
    // A self-service account with a session.
    send(
        &app,
        post("/signup", "email=s%40example.com&name=S&password=correct+horse+battery".into(), None),
    )
    .await;
    let token = |path: &str| {
        let mail = state.accounts.outbox().pending().into_iter().last().unwrap();
        let marker = format!("{path}?token=");
        let i = mail.email.text.find(&marker).unwrap() + marker.len();
        mail.email.text[i..i + 64].to_owned()
    };
    send(&app, post("/verify", format!("token={}", token("/verify")), None)).await;
    let start = send(&app, get(&authorize_uri(""), None)).await;
    let ticket = start.cookie("authcraft_login").unwrap();
    let done = send(
        &app,
        post("/login", "username=s%40example.com&password=correct+horse+battery".into(), Some(&ticket)),
    )
    .await;
    let session = done.cookie("authcraft_session").unwrap();

    send(&app, post("/forgot", "email=s%40example.com".into(), None)).await;
    send(
        &app,
        post("/reset", format!("token={}&password=another+long+passphrase", token("/reset")), None),
    )
    .await;
    let after = send(&app, get(&authorize_uri(""), Some(&session))).await;
    assert_eq!(after.location.as_deref(), Some("/login"), "reset ended the session");
}
