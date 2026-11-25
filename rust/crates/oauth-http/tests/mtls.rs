//! Real TLS end-to-end for RFC 8705 (ADR 0017): a `self_signed_tls_client_auth`
//! client registers its certificate, authenticates at `/token` with only the
//! certificate, receives a certificate-bound token, and UserInfo accepts it
//! only over a connection with the same certificate.

use std::net::SocketAddr;
use std::sync::Arc;

use base64_engine::encode_std;
use oauth::pkce;
use oauth_http::{app, tls, AppState};
use rcgen::{generate_simple_self_signed, CertifiedKey, KeyPair};
use reqwest::{redirect::Policy, Certificate, Client, Identity, StatusCode};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;

const ISSUER: &str = "https://localhost:8089";
const REDIRECT: &str = "https://mtls.example/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Minimal standard-alphabet base64 encoder for the JWK `x5c` member.
mod base64_engine {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode_std(input: &[u8]) -> String {
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}

fn identity(ck: &CertifiedKey<KeyPair>) -> Identity {
    let pem = format!("{}{}", ck.signing_key.serialize_pem(), ck.cert.pem());
    Identity::from_pem(pem.as_bytes()).unwrap()
}

/// HTTPS client trusting `server`, optionally presenting a client certificate.
fn client(addr: SocketAddr, server: &CertifiedKey<KeyPair>, id: Option<Identity>) -> Client {
    let mut b = Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(Certificate::from_der(server.cert.der()).unwrap())
        .redirect(Policy::none())
        .resolve("localhost", addr);
    if let Some(id) = id {
        b = b.identity(id);
    }
    b.build().unwrap()
}

/// The listener runs on an ephemeral port; the AS issuer stays `ISSUER`.
fn url_on(addr: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{path}", addr.port())
}

fn query_param(location: &str, name: &str) -> Option<String> {
    location
        .split_once('?')?
        .1
        .split('&')
        .find_map(|p| p.strip_prefix(&format!("{name}=")).map(str::to_owned))
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

/// Claims of a compact JWT, without verification (the AS signature is
/// checked elsewhere; this test only reads `cnf`).
fn jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    let bytes = jose::b64url::decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn start_server() -> (SocketAddr, CertifiedKey<KeyPair>) {
    start_server_with(AppState::demo_with_issuer(ISSUER)).await
}

async fn start_server_with(state: AppState) -> (SocketAddr, CertifiedKey<KeyPair>) {
    let server_ck = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let config = tls::server_config(
        vec![CertificateDer::from(server_ck.cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_ck.signing_key.serialize_der())),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app(state);
    tokio::spawn(tls::serve_tls(listener, router, Arc::new(config)));
    (addr, server_ck)
}

#[tokio::test]
async fn self_signed_mtls_client_gets_certificate_bound_token() {
    let (addr, server_ck) = start_server().await;
    let client_ck = generate_simple_self_signed(vec!["mtls-client".to_owned()]).unwrap();
    let other_ck = generate_simple_self_signed(vec!["someone-else".to_owned()]).unwrap();
    let mtls = client(addr, &server_ck, Some(identity(&client_ck)));
    let other = client(addr, &server_ck, Some(identity(&other_ck)));
    let plain = client(addr, &server_ck, None);
    let url = |path: &str| url_on(addr, path);

    let disco: Value = plain
        .get(url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disco["tls_client_certificate_bound_access_tokens"], true);
    assert!(disco["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .contains(&Value::from("self_signed_tls_client_auth")));

    // Register the certificate as x5c (RFC 8705 §2.2.2).
    let x5c = encode_std(client_ck.cert.der());
    let reg = plain
        .post(url("/register"))
        .json(&serde_json::json!({
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "self_signed_tls_client_auth",
            "jwks": {"keys": [{"x5c": [x5c]}]},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status(), StatusCode::CREATED);
    let reg: Value = reg.json().await.unwrap();
    assert_eq!(reg["token_endpoint_auth_method"], "self_signed_tls_client_auth");
    let client_id = reg["client_id"].as_str().unwrap().to_owned();

    // Front channel: authorize + login (no client certificate needed).
    let challenge = pkce::challenge_s256(VERIFIER).unwrap();
    let authz = plain
        .get(url(&format!(
            "/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=openid&nonce=n1",
            enc(&client_id),
            enc(REDIRECT),
            enc(&challenge)
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(authz.status(), StatusCode::SEE_OTHER);
    let cookie = authz.headers()["set-cookie"].to_str().unwrap();
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let login = plain
        .post(url("/login"))
        .header("cookie", cookie)
        .form(&[("username", "alice"), ("password", "password")])
        .send()
        .await
        .unwrap();
    let location = login.headers()["location"].to_str().unwrap().to_owned();
    let code = query_param(&location, "code").expect("code");
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("client_id", client_id.as_str()),
        ("code_verifier", VERIFIER),
    ];

    // Wrong certificate and no certificate both fail client authentication.
    for c in [&other, &plain] {
        let res = c.post(url("/token")).form(&form).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["error"], "invalid_client");
    }

    // The registered certificate authenticates and binds the token.
    let res = mtls.post(url("/token")).form(&form).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let tok: Value = res.json().await.unwrap();
    assert_eq!(tok["token_type"], "Bearer");
    let access_token = tok["access_token"].as_str().unwrap().to_owned();
    let expected = oauth::mtls::cert_thumbprint(client_ck.cert.der());
    assert_eq!(jwt_claims(&access_token)["cnf"]["x5t#S256"], expected.as_str());

    // UserInfo: only the bound certificate may use the token.
    let userinfo = |c: &Client| {
        c.get(url("/userinfo"))
            .bearer_auth(&access_token)
            .send()
    };
    assert_eq!(userinfo(&mtls).await.unwrap().status(), StatusCode::OK);
    assert_eq!(userinfo(&other).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(userinfo(&plain).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Introspection (as the self-signed client, over mTLS) reports cnf.
    let info: Value = mtls
        .post(url("/introspect"))
        .form(&[("token", access_token.as_str()), ("client_id", client_id.as_str())])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["active"], true);
    assert_eq!(info["token_type"], "Bearer");
    assert_eq!(info["cnf"]["x5t#S256"], expected.as_str());

    // Refresh: the family is bound to the certificate too.
    let refresh_token = tok["refresh_token"].as_str().unwrap().to_owned();
    let refresh_form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
        ("client_id", client_id.as_str()),
    ];
    let res = other.post(url("/token")).form(&refresh_form).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "wrong cert fails client auth first");
    let res = mtls.post(url("/token")).form(&refresh_form).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// Authorize + login for `client_id` as alice; returns the code.
async fn obtain_code(plain: &Client, base: &dyn Fn(&str) -> String, client_id: &str, redirect: &str) -> String {
    let challenge = pkce::challenge_s256(VERIFIER).unwrap();
    let authz = plain
        .get(base(&format!(
            "/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
            enc(client_id),
            enc(redirect),
            enc(&challenge)
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(authz.status(), StatusCode::SEE_OTHER);
    let cookie = authz.headers()["set-cookie"].to_str().unwrap();
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let login = plain
        .post(base("/login"))
        .header("cookie", cookie)
        .form(&[("username", "alice"), ("password", "password")])
        .send()
        .await
        .unwrap();
    let location = login.headers()["location"].to_str().unwrap().to_owned();
    query_param(&location, "code").expect("code")
}

#[tokio::test]
async fn pki_tls_client_auth_over_real_tls() {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    };
    // A client CA and a leaf it issues for SAN DNS client.example.
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let mut leaf_params = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    let leaf_identity = Identity::from_pem(
        format!("{}{}", leaf_key.serialize_pem(), leaf_cert.pem()).as_bytes(),
    )
    .unwrap();
    // Same SAN, but self-signed: not issued by the trusted CA.
    let impostor = generate_simple_self_signed(vec!["client.example".to_owned()]).unwrap();

    let state = AppState::demo_tls(ISSUER, vec![ca_cert.der().to_vec()]);
    let (addr, server_ck) = start_server_with(state).await;
    let url = |path: &str| url_on(addr, path);
    let plain = client(addr, &server_ck, None);
    let pki = client(addr, &server_ck, Some(leaf_identity));
    let fake = client(addr, &server_ck, Some(identity(&impostor)));

    let redirect = "https://pki.example/cb";
    let reg = plain
        .post(url("/register"))
        .json(&serde_json::json!({
            "redirect_uris": [redirect],
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_auth_san_dns": "client.example",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status(), StatusCode::CREATED);
    let reg: Value = reg.json().await.unwrap();
    assert_eq!(reg["token_endpoint_auth_method"], "tls_client_auth");
    let client_id = reg["client_id"].as_str().unwrap().to_owned();

    let code = obtain_code(&plain, &url, &client_id, redirect).await;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect),
        ("client_id", client_id.as_str()),
        ("code_verifier", VERIFIER),
    ];
    let res = fake.post(url("/token")).form(&form).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "self-signed impostor");
    let res = pki.post(url("/token")).form(&form).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let tok: Value = res.json().await.unwrap();
    let access_token = tok["access_token"].as_str().unwrap();
    assert_eq!(
        jwt_claims(access_token)["cnf"]["x5t#S256"],
        oauth::mtls::cert_thumbprint(leaf_cert.der()).as_str()
    );
}
