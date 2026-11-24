//! Runs `testvectors/oauth/` and `testvectors/oidc/` against the oauth library.

use std::fs;
use std::path::{Path, PathBuf};

use jose::alg::Alg;
use jose::b64url;
use jose::json::{self, Value};
use jose::jwk::PublicKey;
use jose::jwks::Jwks;
use jose::signing::{self, generate_signing_key};
use jose::verify::{self, Policy};
use oauth::id_token;
use oauth::pkce;
use oauth::totp;
use oauth::{
    hash_password, AuthorizationServer, AuthorizeRequest, Client, DynamicClientRequest,
    LoginSubject, OAuthError, ServerConfig, TokenRequest, UserRecord, DEMO_ADMIN_TOKEN,
};

fn oauth_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/oauth")
}

fn oidc_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/oidc")
}

fn token_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/token")
}

fn par_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/par")
}

fn dpop_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/dpop")
}

fn authn_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/authn")
}

fn admin_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/admin")
}

fn client_auth_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/client_auth")
}

fn jar_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/jar")
}

fn introspect_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/introspect")
}

fn mtls_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/mtls")
}

fn dcr_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/dcr")
}

fn make_dpop_proof(
    htm: &str,
    htu: &str,
    iat: i64,
    jti: &str,
    pkcs8: &[u8],
    public: &PublicKey,
    nonce: Option<&str>,
) -> String {
    let x = match public {
        PublicKey::Ed25519 { x } => b64url::encode(x),
        _ => panic!("eddsa"),
    };
    let header = format!(
        r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}}}"#
    );
    let payload = match nonce {
        Some(n) => {
            format!(r#"{{"htm":"{htm}","htu":"{htu}","iat":{iat},"jti":"{jti}","nonce":"{n}"}}"#)
        }
        None => format!(r#"{{"htm":"{htm}","htu":"{htu}","iat":{iat},"jti":"{jti}"}}"#),
    };
    let enc_h = b64url::encode(header.as_bytes());
    let enc_p = b64url::encode(payload.as_bytes());
    let input = format!("{enc_h}.{enc_p}");
    let sig = signing::sign(Alg::EdDSA, pkcs8, input.as_bytes()).unwrap();
    format!("{input}.{}", b64url::encode(&sig))
}

fn string<'a>(v: &'a Value, name: &str) -> &'a str {
    v.get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string {name}"))
}

fn integer(v: &Value, name: &str) -> i64 {
    v.get(name)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("missing int {name}"))
}

fn optional_string<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    v.get(name).and_then(Value::as_str)
}

fn bool_field(v: &Value, name: &str) -> bool {
    match v.get(name) {
        Some(Value::Bool(b)) => *b,
        None => false,
        _ => panic!("{name} must be bool"),
    }
}

/// Single-key JWKS document for a generated signing key (`kid` = thumbprint).
fn jwks_for_key(key: &signing::SigningKey) -> String {
    let kid = key.public.thumbprint();
    format!(
        r#"{{"keys":[{{"kid":"{kid}",{}]}}"#,
        &key.public.canonical_json()[1..]
    )
}

/// RFC 7523 client assertion for `client_id`, valid for 60 s from `now`.
fn client_assertion_for(
    key: &signing::SigningKey,
    client_id: &str,
    jti: &str,
    now: i64,
) -> oauth::ClientCredentials {
    let kid = key.public.thumbprint();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#);
    let exp = now + 60;
    let payload = format!(
        r#"{{"iss":"{client_id}","sub":"{client_id}","aud":"https://auth.example","jti":"{jti}","exp":{exp}}}"#
    );
    oauth::ClientCredentials {
        client_assertion_type: Some(oauth::CLIENT_ASSERTION_TYPE_JWT_BEARER.into()),
        client_assertion: Some(
            signing::sign_compact(Alg::EdDSA, &key.pkcs8, header.as_bytes(), payload.as_bytes())
                .unwrap(),
        ),
        tls_client_cert: None,
    }
}

fn make_server() -> AuthorizationServer {
    let key = generate_signing_key(Alg::EdDSA).expect("key");
    let mut cfg = ServerConfig::new("https://auth.example", "api");
    cfg.admin_token = DEMO_ADMIN_TOKEN.into();
    AuthorizationServer::new(
        cfg,
        vec![Client::new("spa", vec!["https://app.example/cb".into()])],
        key,
    )
}

fn run_code_flow_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    let id = string(&root, "id");
    assert_eq!(id, path.file_stem().unwrap().to_str().unwrap());

    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let ok = match expect.get("ok") {
        Some(Value::Bool(b)) => *b,
        _ => panic!("{case}: expect.ok"),
    };

    let client_id = string(steps, "client_id");
    let redirect_uri = string(steps, "redirect_uri");
    let method = string(steps, "code_challenge_method");
    let verifier = string(steps, "code_verifier");
    let challenge = optional_string(steps, "code_challenge")
        .map(str::to_owned)
        .unwrap_or_else(|| pkce::challenge_s256(verifier).expect("challenge"));
    let subject = string(steps, "subject");
    let now_auth = integer(steps, "now_authorize");
    let now_token = integer(steps, "now_token");

    let srv = make_server();
    let begin = srv.begin_authorize(&AuthorizeRequest {
        response_type: "code".into(),
        client_id: client_id.into(),
        redirect_uri: redirect_uri.into(),
        code_challenge: challenge,
        code_challenge_method: method.into(),
        state: optional_string(steps, "state").map(str::to_owned),
        scope: optional_string(steps, "scope").map(str::to_owned),
        nonce: optional_string(steps, "nonce").map(str::to_owned),
                request_uri: None,
                request: None,
        }, now_auth);

    let phase = optional_string(expect, "phase").unwrap_or(if ok { "token" } else { "authorize" });

    if !ok && phase == "authorize" {
        let err = begin.expect_err("expected authorize failure");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
        return;
    }

    let pending = begin.unwrap_or_else(|e| panic!("{case}: authorize failed: {e}"));
    let login = LoginSubject {
        subject: subject.into(),
        name: optional_string(steps, "name").map(str::to_owned),
        email: optional_string(steps, "email").map(str::to_owned),
    };
    let issued = srv
        .finish_authorize(pending, &login, now_auth)
        .unwrap_or_else(|e| panic!("{case}: finish: {e}"));

    let token_verifier = optional_string(steps, "token_code_verifier").unwrap_or(verifier);
    let token_redirect = optional_string(steps, "token_redirect_uri").unwrap_or(redirect_uri);
    let token_client = optional_string(steps, "token_client_id").unwrap_or(client_id);

    let req = TokenRequest {
        grant_type: "authorization_code".into(),
        code: issued.code.clone(),
        redirect_uri: token_redirect.into(),
        client_id: token_client.into(),
        code_verifier: token_verifier.into(),
        refresh_token: String::new(),
        client_assertion_type: None,
        client_assertion: None,
    };

    let first = srv.exchange_token(&req, now_token, None, "https://auth.example/token");
    if bool_field(steps, "replay_token") {
        first.unwrap_or_else(|e| panic!("{case}: first token: {e}"));
        let second = srv.exchange_token(&req, now_token + 1, None, "https://auth.example/token");
        assert!(!ok);
        let err = second.expect_err("expected replay failure");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
        return;
    }

    if ok {
        let token = first.unwrap_or_else(|e| panic!("{case}: token: {e}"));
        let jwks = Jwks::parse(srv.jwks_document().as_bytes()).unwrap();
        verify::verify(
            token.access_token.as_bytes(),
            &jwks,
            &Policy {
                algorithms: vec![Alg::EdDSA],
                issuer: Some("https://auth.example".into()),
                audience: Some("api".into()),
                now: now_token,
                leeway: 0,
                typ: Some("at+jwt".into()),
                max_token_bytes: 8192,
            },
        )
        .unwrap_or_else(|e| panic!("{case}: jwt verify: {e}"));

        let expect_id = bool_field(expect, "id_token");
        if expect_id {
            let id = token.id_token.as_ref().expect("id_token present");
            let verified = verify::verify(
                id.as_bytes(),
                &jwks,
                &Policy {
                    algorithms: vec![Alg::EdDSA],
                    issuer: Some("https://auth.example".into()),
                    audience: Some(client_id.into()),
                    now: now_token,
                    leeway: 0,
                    typ: Some("JWT".into()),
                    max_token_bytes: 8192,
                },
            )
            .unwrap_or_else(|e| panic!("{case}: id_token verify: {e}"));
            if let Some(nonce) = optional_string(steps, "nonce") {
                assert_eq!(
                    verified.claims.get("nonce").and_then(|v| v.as_str()),
                    Some(nonce),
                    "{case}"
                );
            }
            let expected_hash = id_token::at_hash_eddsa(&token.access_token);
            assert_eq!(
                verified.claims.get("at_hash").and_then(|v| v.as_str()),
                Some(expected_hash.as_str()),
                "{case}"
            );
        } else {
            assert!(token.id_token.is_none(), "{case}: unexpected id_token");
        }

        if bool_field(steps, "check_userinfo") {
            let info = srv
                .userinfo(&token.access_token, now_token, None, "https://auth.example/userinfo")
                .unwrap_or_else(|e| panic!("{case}: userinfo: {e}"));
            assert_eq!(info.sub, subject, "{case}");
            if let Some(name) = optional_string(steps, "name") {
                assert_eq!(info.name.as_deref(), Some(name), "{case}");
            }
            if let Some(email) = optional_string(steps, "email") {
                assert_eq!(info.email.as_deref(), Some(email), "{case}");
            }
        }
    } else {
        let err = first.expect_err("expected token failure");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
    }
}

fn run_userinfo_reject_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    let expect = root.get("expect").expect("expect");
    let srv = make_server();
    let err = srv
        .userinfo("not.a.jwt", 1_000, None, "https://auth.example/userinfo")
        .expect_err("expected userinfo failure");
    assert_eq!(err.code(), string(expect, "error"), "{case}");
}

fn load_json_vectors(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "json")
                && p.file_name() != Some("schema.json".as_ref())
        })
        .collect();
    files.sort();
    files
}

#[test]
fn oauth_shared_vectors() {
    let files = load_json_vectors(&oauth_vectors_dir());
    assert!(!files.is_empty(), "no oauth vectors");
    for f in files {
        run_code_flow_vector(&f);
    }
}

#[test]
fn oidc_shared_vectors() {
    let files = load_json_vectors(&oidc_vectors_dir());
    assert!(!files.is_empty(), "no oidc vectors");
    for f in files {
        let stem = f.file_stem().unwrap().to_str().unwrap();
        if stem.starts_with("neg-userinfo") {
            run_userinfo_reject_vector(&f);
        } else {
            run_code_flow_vector(&f);
        }
    }
}

fn run_token_lifecycle_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(string(&root, "id"), path.file_stem().unwrap().to_str().unwrap());
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let action = string(steps, "action");

    let client_id = string(steps, "client_id");
    let redirect_uri = string(steps, "redirect_uri");
    let verifier = string(steps, "code_verifier");
    let challenge = pkce::challenge_s256(verifier).expect("challenge");
    let now_auth = integer(steps, "now_authorize");
    let now_token = integer(steps, "now_token");
    let now_refresh = integer(steps, "now_refresh");

    let srv = make_server();
    let pending = srv
        .begin_authorize(&AuthorizeRequest {
            response_type: "code".into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            code_challenge: challenge,
            code_challenge_method: string(steps, "code_challenge_method").into(),
            state: None,
            scope: optional_string(steps, "scope").map(str::to_owned),
            nonce: None,
                    request_uri: None,
                    request: None,
        }, now_auth)
        .unwrap_or_else(|e| panic!("{case}: authorize: {e}"));
    let issued = srv
        .finish_authorize(pending, &LoginSubject::new(string(steps, "subject")), now_auth)
        .unwrap();
    let first = srv
        .exchange_token(
            &TokenRequest {
                grant_type: "authorization_code".into(),
                code: issued.code,
                redirect_uri: redirect_uri.into(),
                client_id: client_id.into(),
                code_verifier: verifier.into(),
                refresh_token: String::new(),
                client_assertion_type: None,
                client_assertion: None,
            },
            now_token, None, "https://auth.example/token")
        .unwrap_or_else(|e| panic!("{case}: token: {e}"));
    let rt = first
        .refresh_token
        .clone()
        .expect("refresh_token on code exchange");

    // ADR 0016: introspection callers authenticate; `rs` is a resource server.
    let rs_key = generate_signing_key(Alg::EdDSA).unwrap();
    srv.create_client(
        Some(DEMO_ADMIN_TOKEN),
        Client {
            resource_server: true,
            ..Client::private_key_jwt("rs", Vec::new(), jwks_for_key(&rs_key))
        },
    )
    .unwrap_or_else(|e| panic!("{case}: create rs: {e}"));
    let rs_jti = std::cell::Cell::new(0u32);
    let introspect = |token: &str, hint: oauth::TokenTypeHint| {
        rs_jti.set(rs_jti.get() + 1);
        let auth = client_assertion_for(&rs_key, "rs", &format!("rs-{}", rs_jti.get()), now_token);
        srv.introspect(token, hint, "rs", &auth, now_token)
            .unwrap_or_else(|e| panic!("{case}: introspect: {e}"))
    };

    match action {
        "revoke_access" => {
            assert!(introspect(&first.access_token, oauth::TokenTypeHint::AccessToken).active);
            srv.revoke(
                &first.access_token,
                oauth::TokenTypeHint::AccessToken,
                client_id, &oauth::ClientCredentials::default(),
                now_token,
            )
            .unwrap();
            assert!(!introspect(&first.access_token, oauth::TokenTypeHint::AccessToken).active);
            assert_eq!(
                srv.userinfo(&first.access_token, now_token, None, "https://auth.example/userinfo")
                    .unwrap_err()
                    .code(),
                "invalid_token"
            );
        }
        "revoke_refresh" => {
            srv.revoke(&rt, oauth::TokenTypeHint::RefreshToken, client_id, &oauth::ClientCredentials::default(), now_token)
                .unwrap();
            assert!(!introspect(&rt, oauth::TokenTypeHint::RefreshToken).active);
        }
        "refresh" => {
            let second = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "refresh_token".into(),
                        code: String::new(),
                        redirect_uri: String::new(),
                        client_id: client_id.into(),
                        code_verifier: String::new(),
                        refresh_token: rt,
                        client_assertion_type: None,
                        client_assertion: None,
                    },
                    now_refresh, None, "https://auth.example/token")
                .unwrap_or_else(|e| panic!("{case}: refresh: {e}"));
            assert!(second.refresh_token.is_some(), "{case}");
            assert!(second.id_token.is_none(), "{case}");
            let jwks = Jwks::parse(srv.jwks_document().as_bytes()).unwrap();
            verify::verify(
                second.access_token.as_bytes(),
                &jwks,
                &Policy {
                    algorithms: vec![Alg::EdDSA],
                    issuer: Some("https://auth.example".into()),
                    audience: Some("api".into()),
                    now: now_refresh,
                    leeway: 0,
                    typ: Some("at+jwt".into()),
                    max_token_bytes: 8192,
                },
            )
            .unwrap();
        }
        "refresh_reuse" => {
            let second = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "refresh_token".into(),
                        code: String::new(),
                        redirect_uri: String::new(),
                        client_id: client_id.into(),
                        code_verifier: String::new(),
                        refresh_token: rt.clone(),
                        client_assertion_type: None,
                        client_assertion: None,
                    },
                    now_refresh, None, "https://auth.example/token")
                .unwrap();
            let err = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "refresh_token".into(),
                        code: String::new(),
                        redirect_uri: String::new(),
                        client_id: client_id.into(),
                        code_verifier: String::new(),
                        refresh_token: rt,
                        client_assertion_type: None,
                        client_assertion: None,
                    },
                    now_refresh + 1, None, "https://auth.example/token")
                .expect_err("reuse");
            assert_eq!(err.code(), string(expect, "error"), "{case}");
            let rotated = second.refresh_token.expect("rotated");
            let err2 = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "refresh_token".into(),
                        code: String::new(),
                        redirect_uri: String::new(),
                        client_id: client_id.into(),
                        code_verifier: String::new(),
                        refresh_token: rotated,
                        client_assertion_type: None,
                        client_assertion: None,
                    },
                    now_refresh + 2, None, "https://auth.example/token")
                .expect_err("family dead");
            assert_eq!(err2.code(), "invalid_grant", "{case}");
        }
        other => panic!("{case}: unknown action {other}"),
    }
}

#[test]
fn token_lifecycle_vectors() {
    let files = load_json_vectors(&token_vectors_dir());
    assert!(!files.is_empty(), "no token vectors");
    for f in files {
        run_token_lifecycle_vector(&f);
    }
}

fn run_par_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(string(&root, "id"), path.file_stem().unwrap().to_str().unwrap());
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let action = string(steps, "action");
    let client_id = string(steps, "client_id");
    let redirect_uri = string(steps, "redirect_uri");
    let verifier = string(steps, "code_verifier");
    let challenge = pkce::challenge_s256(verifier).unwrap();
    let now_par = integer(steps, "now_par");
    let now_auth = integer(steps, "now_authorize");
    let now_token = integer(steps, "now_token");

    let srv = make_server();
    let pushed = srv
        .push_authorization(
            &AuthorizeRequest {
                response_type: "code".into(),
                client_id: client_id.into(),
                redirect_uri: redirect_uri.into(),
                code_challenge: challenge,
                code_challenge_method: string(steps, "code_challenge_method").into(),
                state: None,
                scope: optional_string(steps, "scope").map(str::to_owned),
                nonce: None,
                request_uri: None,
                request: None,
            },
            &oauth::ClientCredentials::default(),
            now_par,
        )
        .unwrap_or_else(|e| panic!("{case}: par: {e}"));

    match action {
        "par_exchange" => {
            let pending = srv
                .begin_authorize(
                    &AuthorizeRequest {
                        response_type: String::new(),
                        client_id: client_id.into(),
                        redirect_uri: String::new(),
                        code_challenge: String::new(),
                        code_challenge_method: String::new(),
                        state: None,
                        scope: None,
                        nonce: None,
                        request_uri: Some(pushed.request_uri),
                        request: None,
                    },
                    now_auth,
                )
                .unwrap();
            let issued = srv
                .finish_authorize(pending, &LoginSubject::new(string(steps, "subject")), now_auth)
                .unwrap();
            let tok = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "authorization_code".into(),
                        code: issued.code,
                        redirect_uri: redirect_uri.into(),
                        client_id: client_id.into(),
                        code_verifier: verifier.into(),
                        refresh_token: String::new(),
                        client_assertion_type: None,
                        client_assertion: None,
                    },
                    now_token, None, "https://auth.example/token")
                .unwrap();
            assert!(!tok.access_token.is_empty());
        }
        "par_replay" => {
            srv.begin_authorize(
                &AuthorizeRequest {
                    response_type: String::new(),
                    client_id: client_id.into(),
                    redirect_uri: String::new(),
                    code_challenge: String::new(),
                    code_challenge_method: String::new(),
                    state: None,
                    scope: None,
                    nonce: None,
                    request_uri: Some(pushed.request_uri.clone()),
                    request: None,
                },
                now_auth,
            )
            .unwrap();
            let err = srv
                .begin_authorize(
                    &AuthorizeRequest {
                        response_type: String::new(),
                        client_id: client_id.into(),
                        redirect_uri: String::new(),
                        code_challenge: String::new(),
                        code_challenge_method: String::new(),
                        state: None,
                        scope: None,
                        nonce: None,
                        request_uri: Some(pushed.request_uri),
                        request: None,
                    },
                    now_auth + 1,
                )
                .expect_err("replay");
            assert_eq!(err.code(), string(expect, "error"), "{case}");
        }
        other => panic!("{case}: unknown action {other}"),
    }
}

#[test]
fn par_shared_vectors() {
    let files = load_json_vectors(&par_vectors_dir());
    assert!(!files.is_empty(), "no par vectors");
    for f in files {
        run_par_vector(&f);
    }
}

fn run_dpop_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(string(&root, "id"), path.file_stem().unwrap().to_str().unwrap());
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let action = string(steps, "action");
    let client_id = string(steps, "client_id");
    let redirect_uri = string(steps, "redirect_uri");
    let verifier = string(steps, "code_verifier");
    let now_auth = integer(steps, "now_authorize");
    let now_token = integer(steps, "now_token");

    let srv = make_server();
    let challenge = pkce::challenge_s256(verifier).unwrap();
    let pending = srv
        .begin_authorize(
            &AuthorizeRequest {
                response_type: "code".into(),
                client_id: client_id.into(),
                redirect_uri: redirect_uri.into(),
                code_challenge: challenge,
                code_challenge_method: "S256".into(),
                state: None,
                scope: Some("read".into()),
                nonce: None,
                request_uri: None,
                request: None,
            },
            now_auth,
        )
        .unwrap();
    let issued = srv
        .finish_authorize(pending, &LoginSubject::new(string(steps, "subject")), now_auth)
        .unwrap();

    let dpop_key = generate_signing_key(Alg::EdDSA).unwrap();
    let token_htu = "https://auth.example/token";
    let userinfo_htu = "https://auth.example/userinfo";

    let req = TokenRequest {
        grant_type: "authorization_code".into(),
        code: issued.code.clone(),
        redirect_uri: redirect_uri.into(),
        client_id: client_id.into(),
        code_verifier: verifier.into(),
        refresh_token: String::new(),
        client_assertion_type: None,
        client_assertion: None,
    };

    let exchange_ok = |srv: &AuthorizationServer, jti: &str| {
        let probe = make_dpop_proof(
            "POST",
            token_htu,
            now_token,
            &format!("{jti}-probe"),
            &dpop_key.pkcs8,
            &dpop_key.public,
            None,
        );
        match srv.exchange_token(&req, now_token, Some(&probe), token_htu) {
            Err(OAuthError::UseDpopNonce) => {
                let n = srv.dpop_nonce().unwrap();
                let proof = make_dpop_proof(
                    "POST",
                    token_htu,
                    now_token,
                    jti,
                    &dpop_key.pkcs8,
                    &dpop_key.public,
                    Some(&n),
                );
                srv.exchange_token(&req, now_token, Some(&proof), token_htu)
                    .unwrap()
            }
            Ok(t) => t,
            Err(e) => panic!("{case}: unexpected {e}"),
        }
    };

    match action {
        "dpop_bind" => {
            let tok = exchange_ok(&srv, "j-bind");
            assert_eq!(tok.token_type, string(expect, "token_type"));
            let ui_nonce = tok.dpop_nonce.expect("dpop_nonce after bind");
            let proof2 = make_dpop_proof(
                "GET",
                userinfo_htu,
                now_token,
                "j-ui",
                &dpop_key.pkcs8,
                &dpop_key.public,
                Some(&ui_nonce),
            );
            let info = srv
                .userinfo(&tok.access_token, now_token, Some(&proof2), userinfo_htu)
                .unwrap();
            assert_eq!(info.sub, string(steps, "subject"));
        }
        "dpop_bad_htu" => {
            // Obtain a nonce first with a well-formed probe, then fail on htu.
            let probe = make_dpop_proof(
                "POST",
                token_htu,
                now_token,
                "j-bad-probe",
                &dpop_key.pkcs8,
                &dpop_key.public,
                None,
            );
            let _ = srv.exchange_token(&req, now_token, Some(&probe), token_htu);
            let n = srv.dpop_nonce().unwrap();
            let proof = make_dpop_proof(
                "POST",
                "https://auth.example/wrong",
                now_token,
                "j-bad",
                &dpop_key.pkcs8,
                &dpop_key.public,
                Some(&n),
            );
            let err = srv
                .exchange_token(&req, now_token, Some(&proof), token_htu)
                .expect_err("bad htu");
            assert_eq!(err.code(), string(expect, "error"), "{case}");
        }
        "dpop_userinfo_missing" => {
            let tok = exchange_ok(&srv, "j-miss");
            let err = srv
                .userinfo(&tok.access_token, now_token, None, userinfo_htu)
                .expect_err("missing proof");
            assert_eq!(err.code(), string(expect, "error"), "{case}");
        }
        other => panic!("{case}: unknown action {other}"),
    }
}

#[test]
fn dpop_shared_vectors() {
    let files = load_json_vectors(&dpop_vectors_dir());
    assert!(!files.is_empty(), "no dpop vectors");
    for f in files {
        run_dpop_vector(&f);
    }
}

fn run_authn_vector(path: &Path) {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let root = json::parse(raw.as_bytes()).unwrap_or_else(|e| panic!("json {}: {e}", path.display()));
    let case = string(&root, "id");
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");

    let srv = make_server();
    let username = string(steps, "username");
    let seed_password = string(steps, "seed_password");
    let hash = hash_password(seed_password).expect("hash");
    let subject = optional_string(steps, "subject").unwrap_or(username);
    srv.upsert_user(
        username,
        UserRecord {
            subject: subject.into(),
            user_handle: uuid::Uuid::new_v4(),
            name: optional_string(steps, "name").map(str::to_owned),
            email: optional_string(steps, "email").map(str::to_owned),
            password_hash: hash,
            totp_secret: None,
            webauthn_credentials: Vec::new(),
        },
    );

    match optional_string(steps, "action").unwrap_or("password") {
        "password" => {
            let result = srv.authenticate_password(username, string(steps, "password"));
            if bool_field(expect, "ok") {
                let login = result.unwrap_or_else(|e| panic!("{case}: {e}"));
                assert_eq!(login.subject, string(expect, "subject"), "{case}");
            } else {
                let err = result.expect_err("expected authn failure");
                assert_eq!(err.code(), string(expect, "error"), "{case}");
            }
        }
        "totp" => {
            let secret_b32 = string(steps, "totp_secret");
            srv.set_totp_secret(username, secret_b32).unwrap();
            assert!(srv.user_mfa_enrolled(username));
            let login = srv
                .authenticate_password(username, string(steps, "password"))
                .unwrap_or_else(|e| panic!("{case} password: {e}"));
            let secret = totp::decode_base32(secret_b32).unwrap();
            let now = integer(steps, "now");
            let code = if let Some(c) = optional_string(steps, "code") {
                c.to_owned()
            } else if let Some(at) = steps.get("code_at").and_then(Value::as_i64) {
                totp::generate_code(&secret, at)
            } else {
                totp::generate_code(&secret, now)
            };
            let verify_at = steps
                .get("verify_at")
                .and_then(Value::as_i64)
                .unwrap_or(now);
            let result = srv.verify_totp(username, &code, verify_at);
            if bool_field(expect, "ok") {
                result.unwrap_or_else(|e| panic!("{case}: {e}"));
                assert_eq!(login.subject, string(expect, "subject"), "{case}");
            } else {
                let err = result.expect_err("expected totp failure");
                assert_eq!(err.code(), string(expect, "error"), "{case}");
            }
        }
        other => panic!("{case}: unknown action {other}"),
    }
}

#[test]
fn authn_shared_vectors() {
    let files = load_json_vectors(&authn_vectors_dir());
    assert!(!files.is_empty(), "no authn vectors");
    for f in files {
        run_authn_vector(&f);
    }
}

fn run_admin_vector(path: &Path) {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let root = json::parse(raw.as_bytes()).unwrap_or_else(|e| panic!("json {}: {e}", path.display()));
    let case = string(&root, "id");
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let srv = make_server();
    let token = optional_string(steps, "admin_token");

    match optional_string(steps, "action").unwrap_or("list_clients") {
        "list_clients" => {
            let result = srv.list_clients(token);
            if bool_field(expect, "ok") {
                result.unwrap_or_else(|e| panic!("{case}: {e}"));
            } else {
                let err = result.expect_err("expected admin failure");
                assert_eq!(err.code(), string(expect, "error"), "{case}");
            }
        }
        "create_then_exchange" => {
            let client_id = string(steps, "client_id");
            let redirect_uri = string(steps, "redirect_uri");
            srv.create_client(
                token,
                Client {
                    client_id: client_id.into(),
                    redirect_uris: vec![redirect_uri.into()],
                    client_name: optional_string(steps, "client_name").map(str::to_owned),
                    token_endpoint_auth: Default::default(),
                    require_signed_request_object: false,
                    resource_server: false,
                },
            )
            .unwrap_or_else(|e| panic!("{case}: {e}"));

            let verifier = string(steps, "code_verifier");
            let challenge = string(steps, "code_challenge");
            let now_auth = integer(steps, "now_authorize");
            let now_token = integer(steps, "now_token");
            let pending = srv
                .begin_authorize(
                    &AuthorizeRequest {
                        response_type: "code".into(),
                        client_id: client_id.into(),
                        redirect_uri: redirect_uri.into(),
                        code_challenge: challenge.into(),
                        code_challenge_method: "S256".into(),
                        state: None,
                        scope: Some("read".into()),
                        nonce: None,
                        request_uri: None,
                        request: None,
                    },
                    now_auth,
                )
                .unwrap();
            let issued = srv
                .finish_authorize(pending, &LoginSubject::new(string(steps, "subject")), now_auth)
                .unwrap();
            let tok = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "authorization_code".into(),
                        code: issued.code,
                        redirect_uri: redirect_uri.into(),
                        client_id: client_id.into(),
                        code_verifier: verifier.into(),
                        refresh_token: String::new(),
                        client_assertion_type: None,
                        client_assertion: None,
                    },
                    now_token,
                    None,
                    "",
                )
                .unwrap();
            assert!(!tok.access_token.is_empty(), "{case}");
            assert!(bool_field(expect, "ok"), "{case}");
        }
        other => panic!("{case}: unknown action {other}"),
    }
}

#[test]
fn admin_shared_vectors() {
    let files = load_json_vectors(&admin_vectors_dir());
    assert!(!files.is_empty(), "no admin vectors");
    for f in files {
        run_admin_vector(&f);
    }
}

fn run_dcr_vector(path: &Path) {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let root = json::parse(raw.as_bytes()).unwrap_or_else(|e| panic!("json {}: {e}", path.display()));
    let case = string(&root, "id");
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let srv = make_server();

    match optional_string(steps, "action").unwrap_or("register") {
        "register" => {
            let uris = match steps.get("redirect_uris") {
                Some(Value::Array(arr)) => arr
                    .iter()
                    .map(|v| v.as_str().expect("uri").to_owned())
                    .collect(),
                _ => Vec::new(),
            };
            let result = srv.register_client(&DynamicClientRequest {
                redirect_uris: uris,
                client_name: optional_string(steps, "client_name").map(str::to_owned),
                token_endpoint_auth_method: optional_string(steps, "token_endpoint_auth_method")
                    .map(str::to_owned),
                jwks: optional_string(steps, "jwks").map(str::to_owned),
                require_signed_request_object: bool_field(steps, "require_signed_request_object"),
            });
            if bool_field(expect, "ok") {
                result.unwrap_or_else(|e| panic!("{case}: {e}"));
            } else {
                let err = result.expect_err("expected dcr failure");
                assert_eq!(err.code(), string(expect, "error"), "{case}");
            }
        }
        "register_then_exchange" => {
            let redirect_uri = string(steps, "redirect_uri");
            let reg = srv
                .register_client(&DynamicClientRequest {
                    redirect_uris: vec![redirect_uri.into()],
                    client_name: optional_string(steps, "client_name").map(str::to_owned),
                    token_endpoint_auth_method: Some("none".into()),
                    jwks: None,
                    require_signed_request_object: false,
                })
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            let client_id = &reg.client_id;
            let verifier = string(steps, "code_verifier");
            let challenge = string(steps, "code_challenge");
            let now_auth = integer(steps, "now_authorize");
            let now_token = integer(steps, "now_token");
            let pending = srv
                .begin_authorize(
                    &AuthorizeRequest {
                        response_type: "code".into(),
                        client_id: client_id.clone(),
                        redirect_uri: redirect_uri.into(),
                        code_challenge: challenge.into(),
                        code_challenge_method: "S256".into(),
                        state: None,
                        scope: Some("read".into()),
                        nonce: None,
                        request_uri: None,
                        request: None,
                    },
                    now_auth,
                )
                .unwrap();
            let issued = srv
                .finish_authorize(pending, &LoginSubject::new(string(steps, "subject")), now_auth)
                .unwrap();
            let tok = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "authorization_code".into(),
                        code: issued.code,
                        redirect_uri: redirect_uri.into(),
                        client_id: client_id.clone(),
                        code_verifier: verifier.into(),
                        refresh_token: String::new(),
                        client_assertion_type: None,
                        client_assertion: None,
                    },
                    now_token,
                    None,
                    "",
                )
                .unwrap();
            assert!(!tok.access_token.is_empty(), "{case}");
        }
        other => panic!("{case}: unknown action {other}"),
    }
}

#[test]
fn dcr_shared_vectors() {
    let files = load_json_vectors(&dcr_vectors_dir());
    assert!(!files.is_empty(), "no dcr vectors");
    for f in files {
        run_dcr_vector(&f);
    }
}

/// Client JWKS for `svc` in `testvectors/client_auth/schema.json` (RFC 8037 A.2 public key).
const CLIENT_AUTH_SVC_JWKS: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"rfc8037-a2","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;

/// Server for `testvectors/client_auth/` and `testvectors/jar/`: public `spa`,
/// `private_key_jwt` `svc`, and `svc-strict` (also requires signed request objects).
fn make_confidential_server() -> AuthorizationServer {
    make_confidential_server_with(ServerConfig::new("https://auth.example", "api"))
}

fn make_confidential_server_with(config: ServerConfig) -> AuthorizationServer {
    AuthorizationServer::new(
        config,
        vec![
            Client::new("spa", vec!["https://app.example/cb".into()]),
            Client::private_key_jwt(
                "svc",
                vec!["https://svc.example/cb".into()],
                CLIENT_AUTH_SVC_JWKS,
            ),
            Client {
                require_signed_request_object: true,
                ..Client::private_key_jwt(
                    "svc-strict",
                    vec!["https://svc.example/cb".into()],
                    CLIENT_AUTH_SVC_JWKS,
                )
            },
        ],
        generate_signing_key(Alg::EdDSA).expect("key"),
    )
}

fn run_client_auth_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(string(&root, "id"), path.file_stem().unwrap().to_str().unwrap());
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let client_id = string(steps, "client_id");
    let redirect_uri = string(steps, "redirect_uri");
    let verifier = string(steps, "code_verifier");
    let now_auth = integer(steps, "now_authorize");
    let now_token = integer(steps, "now_token");

    let mut config = ServerConfig::new("https://auth.example", "api");
    config.require_client_assertion_typ = bool_field(steps, "require_client_assertion_typ");
    let srv = make_confidential_server_with(config);
    let authorize_request = || AuthorizeRequest {
        response_type: "code".into(),
        client_id: client_id.into(),
        redirect_uri: redirect_uri.into(),
        code_challenge: pkce::challenge_s256(verifier).unwrap(),
        code_challenge_method: "S256".into(),
        state: None,
        scope: Some("read".into()),
        nonce: None,
        request_uri: None,
        request: None,
    };
    let issue_code = || {
        let pending = srv
            .begin_authorize(&authorize_request(), now_auth)
            .unwrap_or_else(|e| panic!("{case}: {e}"));
        srv.finish_authorize(pending, &LoginSubject::new(string(steps, "subject")), now_auth)
            .unwrap_or_else(|e| panic!("{case}: {e}"))
            .code
    };
    let client_auth = oauth::ClientCredentials {
        client_assertion_type: optional_string(steps, "client_assertion_type").map(str::to_owned),
        client_assertion: optional_string(steps, "client_assertion").map(str::to_owned),
        tls_client_cert: None,
    };
    let exchange = |code: String| {
        srv.exchange_token(
            &TokenRequest {
                grant_type: "authorization_code".into(),
                code,
                redirect_uri: redirect_uri.into(),
                client_id: client_id.into(),
                code_verifier: verifier.into(),
                refresh_token: String::new(),
                client_assertion_type: client_auth.client_assertion_type.clone(),
                client_assertion: client_auth.client_assertion.clone(),
            },
            now_token,
            None,
            "https://auth.example/token",
        )
    };

    // `Some(token)` when the endpoint was /token and succeeded.
    let mut result: Result<Option<oauth::TokenSuccess>, OAuthError> =
        match optional_string(steps, "endpoint").unwrap_or("token") {
            "token" => exchange(issue_code()).map(Some),
            "par" => srv
                .push_authorization(&authorize_request(), &client_auth, now_token)
                .map(|ok| {
                    assert!(ok.request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
                    None
                }),
            "revoke" => srv
                .revoke(
                    string(steps, "token"),
                    oauth::TokenTypeHint::None,
                    client_id,
                    &client_auth,
                    now_token,
                )
                .map(|()| None),
            other => panic!("{case}: unknown endpoint {other}"),
        };
    if bool_field(steps, "replay_assertion") {
        result.unwrap_or_else(|e| panic!("{case}: first use: {e}"));
        // Client authentication runs before the code is redeemed, so the replay
        // fails with invalid_client rather than consuming the code.
        result = exchange(issue_code()).map(Some);
        assert!(
            matches!(result, Err(OAuthError::InvalidClient)),
            "{case}: replay should fail client auth first"
        );
    }

    if bool_field(expect, "ok") {
        let Some(tok) = result.unwrap_or_else(|e| panic!("{case}: {e}")) else {
            return;
        };
        let jwks = Jwks::parse(srv.jwks_document_at(now_token).as_bytes()).unwrap();
        let verified = verify::verify(
            tok.access_token.as_bytes(),
            &jwks,
            &Policy {
                algorithms: vec![Alg::EdDSA],
                issuer: Some("https://auth.example".into()),
                audience: Some("api".into()),
                now: now_token,
                leeway: 0,
                typ: Some("at+jwt".into()),
                max_token_bytes: 8192,
            },
        )
        .unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(
            verified.claims.get("client_id").and_then(Value::as_str),
            Some(client_id),
            "{case}"
        );
    } else {
        let err = result.expect_err("expected client auth failure");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
    }
}

#[test]
fn client_auth_shared_vectors() {
    let files = load_json_vectors(&client_auth_vectors_dir());
    assert!(!files.is_empty(), "no client_auth vectors");
    for f in files {
        run_client_auth_vector(&f);
    }
}

fn run_jar_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(string(&root, "id"), path.file_stem().unwrap().to_str().unwrap());
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let client_id = string(steps, "client_id");
    let now = integer(steps, "now");
    let empty = Value::Object(Vec::new());
    let outer = steps.get("outer").unwrap_or(&empty);
    let outer_str = |name: &str| optional_string(outer, name).map(str::to_owned);

    let srv = make_confidential_server();
    let req = AuthorizeRequest {
        response_type: outer_str("response_type").unwrap_or_default(),
        client_id: client_id.into(),
        redirect_uri: outer_str("redirect_uri").unwrap_or_default(),
        code_challenge: outer_str("code_challenge").unwrap_or_default(),
        code_challenge_method: outer_str("code_challenge_method").unwrap_or_default(),
        state: outer_str("state"),
        scope: outer_str("scope"),
        nonce: outer_str("nonce"),
        request_uri: outer_str("request_uri"),
        request: optional_string(steps, "request").map(str::to_owned),
    };
    let result = match string(steps, "endpoint") {
        "authorize" => srv.begin_authorize(&req, now),
        "par" => {
            let client_auth = oauth::ClientCredentials {
                client_assertion_type: optional_string(steps, "client_assertion_type")
                    .map(str::to_owned),
                client_assertion: optional_string(steps, "client_assertion").map(str::to_owned),
                tls_client_cert: None,
            };
            srv.push_authorization(&req, &client_auth, now).and_then(|par| {
                srv.begin_authorize(
                    &AuthorizeRequest {
                        response_type: String::new(),
                        client_id: client_id.into(),
                        redirect_uri: String::new(),
                        code_challenge: String::new(),
                        code_challenge_method: String::new(),
                        state: None,
                        scope: None,
                        nonce: None,
                        request_uri: Some(par.request_uri),
                        request: None,
                    },
                    now,
                )
            })
        }
        other => panic!("{case}: unknown endpoint {other}"),
    };

    if bool_field(expect, "ok") {
        let pending = result.unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(pending.client_id, client_id, "{case}");
        assert_eq!(pending.redirect_uri, string(expect, "redirect_uri"), "{case}");
        assert_eq!(pending.state.as_deref(), optional_string(expect, "state"), "{case}");
        assert_eq!(pending.code_challenge, string(expect, "code_challenge"), "{case}");
    } else {
        let err = result.expect_err("expected request object failure");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
    }
}

#[test]
fn jar_shared_vectors() {
    let files = load_json_vectors(&jar_vectors_dir());
    assert!(!files.is_empty(), "no jar vectors");
    for f in files {
        run_jar_vector(&f);
    }
}

fn run_introspect_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(string(&root, "id"), path.file_stem().unwrap().to_str().unwrap());
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let verifier = string(steps, "code_verifier");
    let now_auth = integer(steps, "now_authorize");
    let now = integer(steps, "now");
    let token_client = string(steps, "token_client");
    let redirect_uri = string(steps, &format!("redirect_uri_{token_client}"));

    let srv = AuthorizationServer::new(
        ServerConfig::new("https://auth.example", "api"),
        vec![
            Client::new("spa", vec!["https://app.example/cb".into()]),
            Client::private_key_jwt(
                "svc",
                vec!["https://svc.example/cb".into()],
                CLIENT_AUTH_SVC_JWKS,
            ),
            Client {
                resource_server: true,
                ..Client::private_key_jwt("rs", Vec::new(), CLIENT_AUTH_SVC_JWKS)
            },
        ],
        generate_signing_key(Alg::EdDSA).expect("key"),
    );

    let pending = srv
        .begin_authorize(
            &AuthorizeRequest {
                response_type: "code".into(),
                client_id: token_client.into(),
                redirect_uri: redirect_uri.into(),
                code_challenge: pkce::challenge_s256(verifier).unwrap(),
                code_challenge_method: "S256".into(),
                state: None,
                scope: Some("read".into()),
                nonce: None,
                request_uri: None,
                request: None,
            },
            now_auth,
        )
        .unwrap_or_else(|e| panic!("{case}: {e}"));
    let code = srv
        .finish_authorize(pending, &LoginSubject::new(string(steps, "subject")), now_auth)
        .unwrap_or_else(|e| panic!("{case}: {e}"))
        .code;
    let token_assertion = optional_string(steps, "token_client_assertion");
    let tok = srv
        .exchange_token(
            &TokenRequest {
                grant_type: "authorization_code".into(),
                code,
                redirect_uri: redirect_uri.into(),
                client_id: token_client.into(),
                code_verifier: verifier.into(),
                refresh_token: String::new(),
                client_assertion_type: token_assertion
                    .map(|_| oauth::CLIENT_ASSERTION_TYPE_JWT_BEARER.to_owned()),
                client_assertion: token_assertion.map(str::to_owned),
            },
            now,
            None,
            "https://auth.example/token",
        )
        .unwrap_or_else(|e| panic!("{case}: token: {e}"));

    let caller_auth = oauth::ClientCredentials {
        client_assertion_type: optional_string(steps, "caller_assertion_type").map(str::to_owned),
        client_assertion: optional_string(steps, "caller_assertion").map(str::to_owned),
        tls_client_cert: None,
    };
    let result = srv.introspect(
        &tok.access_token,
        oauth::TokenTypeHint::AccessToken,
        string(steps, "caller"),
        &caller_auth,
        now,
    );
    if bool_field(expect, "ok") {
        let info = result.unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(info.active, bool_field(expect, "active"), "{case}");
        assert_eq!(info.client_id.as_deref(), optional_string(expect, "client_id"), "{case}");
    } else {
        let err = result.expect_err("expected introspection failure");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
    }
}

#[test]
fn introspect_shared_vectors() {
    let files = load_json_vectors(&introspect_vectors_dir());
    assert!(!files.is_empty(), "no introspect vectors");
    for f in files {
        run_introspect_vector(&f);
    }
}

/// DER certificates `A` / `B` from `testvectors/mtls/schema.json`.
fn mtls_certs() -> (Vec<u8>, Vec<u8>) {
    let text = fs::read(mtls_vectors_dir().join("schema.json")).unwrap();
    let schema = json::parse(&text).unwrap();
    let certs = schema.get("x-authcraft-certs").expect("x-authcraft-certs");
    let der = |name: &str| {
        let c = certs.get(name).expect("cert");
        let der = b64url::decode(string(c, "der_b64url")).unwrap();
        assert_eq!(oauth::mtls::cert_thumbprint(&der), string(c, "x5t#S256"));
        der
    };
    (der("A"), der("B"))
}

fn run_mtls_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert_eq!(string(&root, "id"), path.file_stem().unwrap().to_str().unwrap());
    let steps = root.get("steps").expect("steps");
    let expect = root.get("expect").expect("expect");
    let client_id = string(steps, "client_id");
    let redirect_uri = string(steps, "redirect_uri");
    let verifier = string(steps, "code_verifier");
    let now_auth = integer(steps, "now_authorize");
    let now = integer(steps, "now_token");

    let (cert_a, cert_b) = mtls_certs();
    // `Some(None)` = step present with null (no certificate).
    let cert_step = |name: &str| -> Option<Option<Vec<u8>>> {
        match steps.get(name)? {
            Value::Null => Some(None),
            Value::String(s) if s == "A" => Some(Some(cert_a.clone())),
            Value::String(s) if s == "B" => Some(Some(cert_b.clone())),
            other => panic!("{case}: bad {name}: {other:?}"),
        }
    };
    let srv = AuthorizationServer::new(
        ServerConfig::new("https://auth.example", "api"),
        vec![
            Client::new("spa", vec!["https://app.example/cb".into()]),
            Client::self_signed_tls(
                "tls",
                vec!["https://tls.example/cb".into()],
                vec![oauth::mtls::cert_thumbprint(&cert_a)],
            ),
        ],
        generate_signing_key(Alg::EdDSA).expect("key"),
    );
    let pending = srv
        .begin_authorize(
            &AuthorizeRequest {
                response_type: "code".into(),
                client_id: client_id.into(),
                redirect_uri: redirect_uri.into(),
                code_challenge: pkce::challenge_s256(verifier).unwrap(),
                code_challenge_method: "S256".into(),
                state: None,
                scope: Some("read".into()),
                nonce: None,
                request_uri: None,
                request: None,
            },
            now_auth,
        )
        .unwrap_or_else(|e| panic!("{case}: {e}"));
    let code = srv
        .finish_authorize(pending, &LoginSubject::new(string(steps, "subject")), now_auth)
        .unwrap_or_else(|e| panic!("{case}: {e}"))
        .code;

    let token_htu = "https://auth.example/token";
    let dpop = bool_field(steps, "dpop").then(|| {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let nonce = srv.dpop_nonce().unwrap();
        make_dpop_proof("POST", token_htu, now, "mtls-dpop", &key.pkcs8, &key.public, Some(&nonce))
    });
    let assertion = optional_string(steps, "client_assertion").map(str::to_owned);
    let token_cert = cert_step("token_cert").flatten();
    let fail = |phase: &str, err: OAuthError| {
        assert!(!bool_field(expect, "ok"), "{case}: {phase} failed: {err}");
        assert_eq!(string(expect, "phase"), phase, "{case}");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
    };

    let mut tok = match srv.exchange_token_tls(
        &TokenRequest {
            grant_type: "authorization_code".into(),
            code,
            redirect_uri: redirect_uri.into(),
            client_id: client_id.into(),
            code_verifier: verifier.into(),
            refresh_token: String::new(),
            client_assertion_type: assertion
                .as_ref()
                .map(|_| oauth::CLIENT_ASSERTION_TYPE_JWT_BEARER.to_owned()),
            client_assertion: assertion,
        },
        now,
        dpop.as_deref(),
        token_htu,
        token_cert.as_deref(),
    ) {
        Ok(t) => t,
        Err(e) => return fail("token", e),
    };

    if let Some(cert) = cert_step("userinfo_cert") {
        if let Err(e) = srv.userinfo_tls(
            &tok.access_token,
            now,
            None,
            "https://auth.example/userinfo",
            cert.as_deref(),
        ) {
            return fail("userinfo", e);
        }
    }
    if let Some(cert) = cert_step("refresh_cert") {
        let rt = tok.refresh_token.clone().expect("refresh_token");
        tok = match srv.exchange_token_tls(
            &TokenRequest {
                grant_type: "refresh_token".into(),
                code: String::new(),
                redirect_uri: String::new(),
                client_id: client_id.into(),
                code_verifier: String::new(),
                refresh_token: rt,
                client_assertion_type: None,
                client_assertion: None,
            },
            now,
            None,
            token_htu,
            cert.as_deref(),
        ) {
            Ok(t) => t,
            Err(e) => return fail("refresh", e),
        };
    }

    assert!(bool_field(expect, "ok"), "{case}: expected a failure");
    assert_eq!(tok.token_type, string(expect, "token_type"), "{case}");
    let payload = tok.access_token.split('.').nth(1).unwrap();
    let claims = json::parse(&b64url::decode(payload).unwrap()).unwrap();
    let x5t = claims
        .get("cnf")
        .and_then(|c| c.get("x5t#S256"))
        .and_then(Value::as_str);
    let want = match expect.get("cnf_x5t") {
        Some(Value::String(s)) if s == "A" => Some(oauth::mtls::cert_thumbprint(&cert_a)),
        Some(Value::String(s)) if s == "B" => Some(oauth::mtls::cert_thumbprint(&cert_b)),
        _ => None,
    };
    assert_eq!(x5t, want.as_deref(), "{case}");
}

#[test]
fn mtls_shared_vectors() {
    let files = load_json_vectors(&mtls_vectors_dir());
    assert!(!files.is_empty(), "no mtls vectors");
    for f in files {
        run_mtls_vector(&f);
    }
}
