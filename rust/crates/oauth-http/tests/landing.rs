//! The public landing page (ADR 0027).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use oauth::{Client, ServerConfig};
use oauth_http::{app, AppState};
use tower::ServiceExt;

async fn landing(state: AppState) -> (StatusCode, String) {
    let res = app(state)
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn lists_configured_apps_by_origin() {
    let named = |id: &str, name: &str, uri: &str| Client {
        client_name: Some(name.into()),
        ..Client::new(id, vec![uri.into()])
    };
    let state = AppState::production(
        ServerConfig::new("https://authcraft.accumu.cc", "api"),
        vec![
            named("tacto", "Tacto", "https://tacto.accumu.cc/auth/authcraft/callback"),
            named("glossa", "Glossa <beta>", "https://glossa.accumu.cc/auth/authcraft/callback"),
        ],
        jose::signing::generate_signing_key(jose::alg::Alg::EdDSA).unwrap(),
    )
    .unwrap();
    let (status, body) = landing(state).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"<a href="https://tacto.accumu.cc">Tacto</a>"#), "{body}");
    assert!(body.contains("Glossa &lt;beta&gt;"), "client names are escaped");
    assert!(body.contains("https://authcraft.accumu.cc"));
    assert!(body.contains("/signup"));
    assert!(!body.contains("alice"));
}

#[tokio::test]
async fn demo_clients_without_https_or_names_are_not_listed() {
    let (_, body) = landing(AppState::demo()).await;
    assert!(!body.contains("Sign in with authcraft on"));
}

#[tokio::test]
async fn favicons_are_served_with_cache_headers() {
    for (path, ctype) in [("/favicon.svg", "image/svg+xml"), ("/favicon.ico", "image/x-icon")] {
        let res = app(AppState::demo())
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        assert_eq!(res.headers()["content-type"], ctype);
        assert_eq!(res.headers()["cache-control"], "public, max-age=604800");
    }
}
