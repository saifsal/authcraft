//! HTTP end-to-end for self-service accounts (ADR 0025): sign-up, verify,
//! login through the authorization-code flow, enumeration resistance,
//! password reset, and login throttling.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use oauth::pkce;
use oauth_http::{app, AppState};
use tower::ServiceExt;

const PW: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT: &str = "https://app.example/cb";

struct Resp {
    status: StatusCode,
    location: Option<String>,
    cookie: Option<String>,
    body: String,
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let location = res
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_owned());
    let cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok()?.split(';').next().map(str::to_owned));
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        location,
        cookie,
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

fn form(uri: &str, pairs: &[(&str, &str)], cookie: Option<&str>) -> Request<Body> {
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-forwarded-for", "203.0.113.7");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::from(body)).unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

/// The token from the newest queued mail to `to` for `path`.
fn mailed_token(state: &AppState, to: &str, path: &str) -> String {
    let mail = state
        .accounts
        .outbox()
        .pending()
        .into_iter()
        .rev()
        .find(|m| m.email.to == to)
        .expect("mail queued");
    let marker = format!("{path}?token=");
    let start = mail.email.text.find(&marker).expect("link in mail") + marker.len();
    mail.email.text[start..start + 64].to_owned()
}

/// Starts an authorize request and returns the login-ticket cookie.
async fn begin_login(app: &Router) -> String {
    let challenge = pkce::challenge_s256(VERIFIER).unwrap();
    let res = send(
        app,
        get(&format!(
            "/authorize?response_type=code&client_id=spa&redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=openid&nonce=n1",
            enc(REDIRECT),
            enc(&challenge)
        )),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    res.cookie.expect("ticket cookie")
}

#[tokio::test]
async fn signup_verify_and_sign_in() {
    let state = AppState::demo();
    let app = app(state.clone());

    let res = send(
        &app,
        form("/signup", &[("email", "Bea@Example.com"), ("name", "Bea"), ("password", PW)], None),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Check your email"));

    // Unverified: the right password is refused with a hint, and a new link goes out.
    let cookie = begin_login(&app).await;
    let res = send(
        &app,
        form("/login", &[("username", "bea@example.com"), ("password", PW)], Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert!(res.body.contains("Confirm your email address first"));

    // GET shows a confirm form and does not consume the link.
    let token = mailed_token(&state, "Bea@Example.com", "/verify");
    let page = send(&app, get(&format!("/verify?token={token}"))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Confirm email"));
    let res = send(&app, form("/verify", &[("token", &token)], None)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("Email confirmed"));

    // Now the authorization-code flow completes with the new account.
    let cookie = begin_login(&app).await;
    let res = send(
        &app,
        form("/login", &[("username", "BEA@example.com"), ("password", PW)], Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let location = res.location.unwrap();
    assert!(location.starts_with(REDIRECT), "{location}");
    assert!(location.contains("code="));
}

#[tokio::test]
async fn responses_do_not_reveal_accounts() {
    let state = AppState::demo();
    let app = app(state.clone());
    send(&app, form("/signup", &[("email", "k@example.com"), ("name", "K"), ("password", PW)], None)).await;
    let token = mailed_token(&state, "k@example.com", "/verify");
    send(&app, form("/verify", &[("token", &token)], None)).await;

    let known = send(&app, form("/signup", &[("email", "k@example.com"), ("name", "K"), ("password", PW)], None)).await;
    let unknown = send(&app, form("/signup", &[("email", "u@example.com"), ("name", "U"), ("password", PW)], None)).await;
    assert_eq!(known.status, unknown.status);
    assert_eq!(known.body, unknown.body);

    let known = send(&app, form("/forgot", &[("email", "k@example.com")], None)).await;
    let unknown = send(&app, form("/forgot", &[("email", "nobody@example.com")], None)).await;
    assert_eq!(known.status, unknown.status);
    assert_eq!(known.body, unknown.body);
}

#[tokio::test]
async fn password_reset_over_http() {
    let state = AppState::demo();
    let app = app(state.clone());
    send(&app, form("/signup", &[("email", "r@example.com"), ("name", "R"), ("password", PW)], None)).await;
    send(&app, form("/forgot", &[("email", "r@example.com")], None)).await;
    let token = mailed_token(&state, "r@example.com", "/reset");

    assert_eq!(send(&app, get(&format!("/reset?token={token}"))).await.status, StatusCode::OK);
    let weak = send(&app, form("/reset", &[("token", &token), ("password", "short")], None)).await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);
    let ok = send(&app, form("/reset", &[("token", &token), ("password", "a brand new passphrase")], None)).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    // Burned.
    assert_eq!(send(&app, get(&format!("/reset?token={token}"))).await.status, StatusCode::BAD_REQUEST);

    // The reset also verified the address, so the account signs in.
    let cookie = begin_login(&app).await;
    let res = send(
        &app,
        form("/login", &[("username", "r@example.com"), ("password", "a brand new passphrase")], Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn login_is_throttled_per_account() {
    let app = app(AppState::demo());
    let cookie = begin_login(&app).await;
    for _ in 0..oauth_http::accounts::LOGIN_PER_ACCOUNT {
        let res = send(
            &app,
            form("/login", &[("username", "alice"), ("password", "wrong password")], Some(&cookie)),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }
    // Locked: even the right password is refused for now.
    let res = send(
        &app,
        form("/login", &[("username", "alice"), ("password", "password")], Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn production_login_page_has_no_demo_hints() {
    let demo_app = app(AppState::demo());
    let demo = send(&demo_app, get("/login")).await;
    assert!(demo.body.contains("alice"));

    let prod = oauth_http::AppState::production(
        oauth::ServerConfig::new("https://auth.example", "api"),
        Vec::new(),
        jose::signing::generate_signing_key(jose::alg::Alg::EdDSA).unwrap(),
    )
    .unwrap();
    let page = send(&app(prod), get("/login")).await;
    assert!(!page.body.contains("alice"), "no demo credentials in production");
    assert!(page.body.contains("/signup"));
}
