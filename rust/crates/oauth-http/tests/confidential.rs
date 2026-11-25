//! HTTP end-to-end for confidential clients (ADR 0014–0016): DCR with
//! `private_key_jwt` + `require_signed_request_object`, PAR with a JAR request
//! object, token / revoke / introspect client authentication, and an
//! admin-registered resource server.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use jose::alg::Alg;
use jose::signing::{generate_signing_key, sign_compact, SigningKey};
use oauth::pkce;
use oauth::DEMO_ADMIN_TOKEN;
use oauth_http::{app, AppState};
use serde_json::Value;
use tower::ServiceExt;

const ISSUER: &str = "http://localhost:8089";
const REDIRECT: &str = "https://svc.example/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

struct Resp {
    status: StatusCode,
    location: Option<String>,
    cookie: Option<String>,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }
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

fn post_form(uri: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

fn post_json(uri: &str, bearer: Option<&str>, body: String) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body)).unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn enc(s: &str) -> String {
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

fn query_param(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// JWKS JSON object (as a string) for one generated key.
fn jwks_for(key: &SigningKey) -> String {
    format!(
        r#"{{"keys":[{{"kid":"{}",{}]}}"#,
        key.public.thumbprint(),
        &key.public.canonical_json()[1..]
    )
}

fn sign(key: &SigningKey, typ: Option<&str>, claims: &Value) -> String {
    let header = match typ {
        Some(t) => format!(r#"{{"alg":"EdDSA","kid":"{}","typ":"{t}"}}"#, key.public.thumbprint()),
        None => format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, key.public.thumbprint()),
    };
    sign_compact(Alg::EdDSA, &key.pkcs8, header.as_bytes(), claims.to_string().as_bytes()).unwrap()
}

fn assertion(key: &SigningKey, client_id: &str, jti: &str) -> String {
    sign(
        key,
        Some("client-authentication+jwt"),
        &serde_json::json!({
            "iss": client_id, "sub": client_id, "aud": ISSUER,
            "jti": jti, "exp": now_unix() + 60,
        }),
    )
}

#[tokio::test]
async fn confidential_client_full_flow_over_http() {
    let app = app(AppState::demo());
    let client_key = generate_signing_key(Alg::EdDSA).unwrap();
    let rs_key = generate_signing_key(Alg::EdDSA).unwrap();

    // Discovery advertises the confidential-client features.
    let disco = send(&app, get("/.well-known/openid-configuration")).await.json();
    assert_eq!(
        disco["token_endpoint_auth_methods_supported"],
        serde_json::json!(["none", "private_key_jwt", "self_signed_tls_client_auth", "tls_client_auth"])
    );
    assert_eq!(disco["request_parameter_supported"], true);
    assert_eq!(
        disco["introspection_endpoint_auth_methods_supported"],
        serde_json::json!(["private_key_jwt", "self_signed_tls_client_auth", "tls_client_auth"])
    );

    // RFC 7591 registration with an inline JWKS object.
    let reg = send(
        &app,
        post_json(
            "/register",
            None,
            format!(
                r#"{{"redirect_uris":["{REDIRECT}"],"token_endpoint_auth_method":"private_key_jwt","jwks":{},"require_signed_request_object":true}}"#,
                jwks_for(&client_key)
            ),
        ),
    )
    .await;
    assert_eq!(reg.status, StatusCode::CREATED, "{}", reg.body);
    let reg = reg.json();
    assert_eq!(reg["token_endpoint_auth_method"], "private_key_jwt");
    assert_eq!(reg["require_signed_request_object"], true);
    let client_id = reg["client_id"].as_str().unwrap().to_owned();

    // Plain front-channel parameters are refused for this client.
    let challenge = pkce::challenge_s256(VERIFIER).unwrap();
    let plain = send(
        &app,
        get(&format!(
            "/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
            enc(&client_id),
            enc(REDIRECT),
            enc(&challenge)
        )),
    )
    .await;
    assert_eq!(plain.status, StatusCode::BAD_REQUEST);
    assert_eq!(plain.json()["error"], "invalid_request");

    // PAR with a signed request object; unauthenticated push is 401.
    let request_object = sign(
        &client_key,
        Some("oauth-authz-req+jwt"),
        &serde_json::json!({
            "iss": client_id, "aud": ISSUER, "client_id": client_id,
            "exp": now_unix() + 60, "response_type": "code",
            "redirect_uri": REDIRECT, "code_challenge": challenge,
            "code_challenge_method": "S256", "state": "jar-state", "scope": "read",
        }),
    );
    let unauth = send(
        &app,
        post_form("/par", &[("client_id", &client_id), ("request", &request_object)]),
    )
    .await;
    assert_eq!(unauth.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth.json()["error"], "invalid_client");

    let par = send(
        &app,
        post_form(
            "/par",
            &[
                ("client_id", &client_id),
                ("request", &request_object),
                ("client_assertion_type", JWT_BEARER),
                ("client_assertion", &assertion(&client_key, &client_id, "par-1")),
            ],
        ),
    )
    .await;
    assert_eq!(par.status, StatusCode::OK, "{}", par.body);
    let request_uri = par.json()["request_uri"].as_str().unwrap().to_owned();

    // Authorize via request_uri, log in, receive the code with signed state.
    let authz = send(
        &app,
        get(&format!(
            "/authorize?client_id={}&request_uri={}",
            enc(&client_id),
            enc(&request_uri)
        )),
    )
    .await;
    assert_eq!(authz.status, StatusCode::SEE_OTHER, "{}", authz.body);
    let login = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::COOKIE, authz.cookie.unwrap())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("username=alice&password=password"))
            .unwrap(),
    )
    .await;
    let location = login.location.expect("redirect");
    assert!(location.starts_with(REDIRECT), "{location}");
    assert_eq!(query_param(&location, "state").as_deref(), Some("jar-state"));
    let code = query_param(&location, "code").expect("code");

    // Token without client authentication is 401; with it, 200.
    let token_form = |assertion: Option<&str>| {
        let mut pairs = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("client_id", client_id.as_str()),
            ("code_verifier", VERIFIER),
        ];
        if let Some(a) = assertion {
            pairs.push(("client_assertion_type", JWT_BEARER));
            pairs.push(("client_assertion", a));
        }
        post_form("/token", &pairs)
    };
    let no_auth = send(&app, token_form(None)).await;
    assert_eq!(no_auth.status, StatusCode::UNAUTHORIZED);
    assert_eq!(no_auth.json()["error"], "invalid_client");
    let tok = send(&app, token_form(Some(&assertion(&client_key, &client_id, "tok-1")))).await;
    assert_eq!(tok.status, StatusCode::OK, "{}", tok.body);
    let tok = tok.json();
    let access_token = tok["access_token"].as_str().unwrap().to_owned();
    let refresh_token = tok["refresh_token"].as_str().unwrap().to_owned();

    // Admin registers a resource server (no redirect URIs).
    let rs = send(
        &app,
        post_json(
            "/admin/clients",
            Some(DEMO_ADMIN_TOKEN),
            format!(
                r#"{{"client_id":"rs","redirect_uris":[],"token_endpoint_auth_method":"private_key_jwt","jwks":{},"resource_server":true}}"#,
                jwks_for(&rs_key)
            ),
        ),
    )
    .await;
    assert_eq!(rs.status, StatusCode::CREATED, "{}", rs.body);
    assert_eq!(rs.json()["resource_server"], true);

    // Introspection: anonymous 401; resource server sees the token.
    let anon = send(&app, post_form("/introspect", &[("token", &access_token)])).await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
    let introspect_as_rs = |token: String, jti: &'static str| {
        post_form(
            "/introspect",
            &[
                ("token", &token),
                ("client_id", "rs"),
                ("client_assertion_type", JWT_BEARER),
                ("client_assertion", &assertion(&rs_key, "rs", jti)),
            ],
        )
    };
    let info = send(&app, introspect_as_rs(access_token, "rs-1")).await.json();
    assert_eq!(info["active"], true);
    assert_eq!(info["client_id"], client_id.as_str());

    // Revocation needs client authentication; then the refresh token is dead.
    let revoke_form = |assertion: Option<String>| {
        let mut pairs = vec![
            ("token".to_owned(), refresh_token.clone()),
            ("token_type_hint".to_owned(), "refresh_token".to_owned()),
            ("client_id".to_owned(), client_id.clone()),
        ];
        if let Some(a) = assertion {
            pairs.push(("client_assertion_type".to_owned(), JWT_BEARER.to_owned()));
            pairs.push(("client_assertion".to_owned(), a));
        }
        let pairs: Vec<(&str, &str)> =
            pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        post_form("/revoke", &pairs)
    };
    assert_eq!(send(&app, revoke_form(None)).await.status, StatusCode::UNAUTHORIZED);
    let revoked = send(
        &app,
        revoke_form(Some(assertion(&client_key, &client_id, "rev-1"))),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    let info = send(&app, introspect_as_rs(refresh_token.clone(), "rs-2")).await.json();
    assert_eq!(info["active"], false);
}

#[tokio::test]
async fn admin_rejects_inconsistent_client_metadata() {
    let app = app(AppState::demo());
    let key = generate_signing_key(Alg::EdDSA).unwrap();
    for body in [
        // jwks without private_key_jwt
        format!(r#"{{"client_id":"a","redirect_uris":["{REDIRECT}"],"jwks":{}}}"#, jwks_for(&key)),
        // private_key_jwt without jwks
        format!(r#"{{"client_id":"b","redirect_uris":["{REDIRECT}"],"token_endpoint_auth_method":"private_key_jwt"}}"#),
        // public resource server
        r#"{"client_id":"c","redirect_uris":[],"resource_server":true}"#.to_owned(),
        // DPoP and certificate binding together (ADR 0018)
        format!(r#"{{"client_id":"d","redirect_uris":["{REDIRECT}"],"dpop_bound_access_tokens":true,"tls_client_certificate_bound_access_tokens":true}}"#),
    ] {
        let res = send(&app, post_json("/admin/clients", Some(DEMO_ADMIN_TOKEN), body.clone())).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{body}: {}", res.body);
    }
}

#[tokio::test]
async fn registration_echoes_policy_and_token_requires_dpop() {
    let app = app(AppState::demo());
    let reg = send(
        &app,
        post_json(
            "/register",
            None,
            format!(r#"{{"redirect_uris":["{REDIRECT}"],"dpop_bound_access_tokens":true}}"#),
        ),
    )
    .await;
    assert_eq!(reg.status, StatusCode::CREATED, "{}", reg.body);
    let reg = reg.json();
    assert_eq!(reg["dpop_bound_access_tokens"], true);
    assert_eq!(reg["require_pushed_authorization_requests"], false);
    let client_id = reg["client_id"].as_str().unwrap().to_owned();

    // Bearer token request from a dpop_bound_access_tokens client: 400.
    let res = send(
        &app,
        post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", "unused"),
                ("redirect_uri", REDIRECT),
                ("client_id", &client_id),
                ("code_verifier", VERIFIER),
            ],
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json()["error"], "invalid_request");
}

#[tokio::test]
async fn security_headers_on_login_and_token_responses() {
    let app = app(AppState::demo());
    let login = app.clone().oneshot(get("/login")).await.unwrap();
    let h = login.headers();
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["content-security-policy"], "frame-ancestors 'none'");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert!(h.get("cache-control").is_none(), "login page is not a token response");

    let token = app
        .oneshot(post_form("/token", &[("grant_type", "authorization_code")]))
        .await
        .unwrap();
    let h = token.headers();
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["pragma"], "no-cache");
    assert_eq!(h["x-frame-options"], "DENY");
}

#[tokio::test]
async fn password_and_client_credentials_grants_are_unsupported() {
    let app = app(AppState::demo());
    for grant in ["password", "client_credentials", "implicit"] {
        let res = send(
            &app,
            post_form(
                "/token",
                &[("grant_type", grant), ("client_id", "spa"), ("username", "alice"), ("password", "password")],
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{grant}");
        assert_eq!(res.json()["error"], "unsupported_grant_type", "{grant}");
    }
}
