//! End-to-end authorize → login → token → jose verify (+ OIDC).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use jose::alg::Alg;
use jose::jwks::Jwks;
use jose::verify::{self, Policy};
use oauth::id_token;
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
                .body(Body::from("username=alice&password=password"))
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
    assert!(json_string_field(&body, "id_token").is_none());

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
    let now = now_unix();
    verify::verify(
        access_token.as_bytes(),
        &jwks,
        &Policy {
            algorithms: vec![Alg::EdDSA],
            issuer: Some("http://localhost:8089".into()),
            audience: Some("api".into()),
            now,
            leeway: 5,
            typ: Some("at+jwt".into()),
            max_token_bytes: 8192,
        },
    )
    .expect("access token verifies");
}

#[tokio::test]
async fn openid_flow_id_token_and_userinfo() {
    let state = AppState::demo();
    let app = app(state.clone());

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce::challenge_s256(verifier).unwrap();
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id=spa&redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=openid%20profile%20email&nonce=n-0S6_WzA2Mj",
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
    let cookie = cookie_from(&res);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "username=alice&password=password",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let code = query_param(&location, "code").expect("code");

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
    let id_token = json_string_field(&body, "id_token").expect("id_token");

    let disc = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disc.status(), StatusCode::OK);
    let disc_body = body_string(disc).await;
    assert!(disc_body.contains("\"userinfo_endpoint\""));

    let jwks_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwks = Jwks::parse(body_string(jwks_res).await.as_bytes()).unwrap();
    let now = now_unix();
    let id_verified = verify::verify(
        id_token.as_bytes(),
        &jwks,
        &Policy {
            algorithms: vec![Alg::EdDSA],
            issuer: Some("http://localhost:8089".into()),
            audience: Some("spa".into()),
            now,
            leeway: 5,
            typ: Some("JWT".into()),
            max_token_bytes: 8192,
        },
    )
    .expect("id_token verifies");
    assert_eq!(
        id_verified.claims.get("at_hash").and_then(|v| v.as_str()),
        Some(id_token::at_hash_eddsa(&access_token).as_str())
    );

    let res = app
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let info = body_string(res).await;
    assert!(info.contains("\"sub\":\"alice\""));
    assert!(info.contains("\"name\":\"Alice\""));
    assert!(info.contains("\"email\":\"alice@example.com\""));
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn dynamic_client_registration_then_token() {
    let state = AppState::demo();
    let app = app(state.clone());

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"redirect_uris":["https://dyn.example/cb"],"client_name":"Dyn","token_endpoint_auth_method":"none"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = body_string(res).await;
    let client_id = json_string_field(&body, "client_id").expect("client_id");

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce::challenge_s256(verifier).unwrap();
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=dcr",
        urlencoding_encode(&client_id),
        urlencoding_encode("https://dyn.example/cb"),
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
    let cookie = cookie_from(&res);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=password"))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let code = query_param(&location, "code").expect("code");
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        urlencoding_encode(&code),
        urlencoding_encode("https://dyn.example/cb"),
        urlencoding_encode(&client_id),
        urlencoding_encode(verifier),
    );
    let res = app
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
    assert!(json_string_field(&body_string(res).await, "access_token").is_some());
}

#[tokio::test]
async fn password_then_webauthn_issues_code() {
    use url::Url;
    use webauthn_authenticator_rs::prelude::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

    let state = AppState::demo();
    let app = app(state.clone());
    let mut token = SoftPasskey::new(true);
    let origin = Url::parse("http://localhost:8089").unwrap();

    let start = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/enroll/webauthn/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=password"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::OK);
    let ccr: CreationChallengeResponse =
        serde_json::from_str(&body_string(start).await).unwrap();
    let reg = token.do_registration(origin.clone(), ccr).unwrap();

    let finish = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/enroll/webauthn/finish")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": "alice",
                        "credential": reg,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(finish.status(), StatusCode::OK);

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce::challenge_s256(verifier).unwrap();
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id=spa&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=wa",
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
    let cookie = cookie_from(&res);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=password"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/login/mfa");

    let start = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/mfa/webauthn/start")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::OK);
    let rcr: RequestChallengeResponse = serde_json::from_str(&body_string(start).await).unwrap();
    let assertion = token.do_authentication(origin, rcr).unwrap();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/mfa/webauthn/finish")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&assertion).unwrap()))
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
    assert!(query_param(&location, "code").is_some());
}

#[tokio::test]
async fn password_then_totp_issues_code() {
    use oauth::totp;

    let state = AppState::demo();
    let app = app(state.clone());

    let enroll = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/enroll/totp")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=password"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enroll.status(), StatusCode::OK);
    let enroll_body = body_string(enroll).await;
    let secret_b32 = json_string_field(&enroll_body, "secret").expect("secret");
    let secret = totp::decode_base32(&secret_b32).unwrap();
    let code = totp::generate_code(&secret, now_unix());

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce::challenge_s256(verifier).unwrap();
    let authorize_uri = format!(
        "/authorize?response_type=code&client_id=spa&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=mfa",
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
    let cookie = cookie_from(&res);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=password"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/login/mfa");

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/mfa")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("code={code}")))
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
    assert!(query_param(&location, "code").is_some());
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
