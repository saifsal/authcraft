//! End-to-end authorize → login → token → jose verify.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use jose::alg::Alg;
use jose::jwks::Jwks;
use jose::verify::{self, Policy};
use oauth::pkce;
use oauth_http::{app, AppState};
use tower::ServiceExt;

async fn body_string(res: axum::response::Response) -> String {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn cookie_from(res: &axum::response::Response) -> String {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            s.split(';').next().map(str::to_owned)
        })
        .expect("set-cookie")
}

#[tokio::test]
async fn authorize_login_token_verifies() {
    let state = AppState::demo();
    let app = app(state.clone());

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce::challenge_s256(verifier).unwrap();

    let authorize_uri = format!(
        "/authorize?response_type=code&client_id=spa&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=xyz&scope=read",
        urlencoding_encode("https://app.example/cb"),
        urlencoding_encode(&challenge),
    );

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&authorize_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/login");
    let cookie = cookie_from(&res);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("subject=alice"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let location = res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(location.starts_with("https://app.example/cb?"));
    let code = query_param(&location, "code").expect("code");
    assert_eq!(query_param(&location, "state").as_deref(), Some("xyz"));

    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id=spa&code_verifier={}",
        urlencoding_encode(&code),
        urlencoding_encode("https://app.example/cb"),
        urlencoding_encode(verifier),
    );
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    let access_token = json_string_field(&body, "access_token").expect("access_token");

    let jwks_res = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwks_body = body_string(jwks_res).await;
    let jwks = Jwks::parse(jwks_body.as_bytes()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    verify::verify(
        access_token.as_bytes(),
        &jwks,
        &Policy {
            algorithms: vec![Alg::EdDSA],
            issuer: Some("http://127.0.0.1:8089".into()),
            audience: Some("api".into()),
            now,
            leeway: 5,
            typ: Some("at+jwt".into()),
            max_token_bytes: 8192,
        },
    )
    .expect("access token verifies");
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == name {
            return Some(urlencoding_decode(v));
        }
    }
    None
}

fn json_string_field(body: &str, name: &str) -> Option<String> {
    // Tiny extractor avoiding a full JSON dependency API in the test.
    let key = format!("\"{name}\":\"");
    let start = body.find(&key)? + key.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
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

fn urlencoding_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}
