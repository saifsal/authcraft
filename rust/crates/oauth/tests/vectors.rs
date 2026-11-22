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
use oauth::{
    AuthorizationServer, AuthorizeRequest, Client, LoginSubject, ServerConfig, TokenRequest,
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

fn make_dpop_proof(htm: &str, htu: &str, iat: i64, jti: &str, pkcs8: &[u8], public: &PublicKey) -> String {
    let x = match public {
        PublicKey::Ed25519 { x } => b64url::encode(x),
        _ => panic!("eddsa"),
    };
    let header = format!(
        r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}}}"#
    );
    let payload = format!(r#"{{"htm":"{htm}","htu":"{htu}","iat":{iat},"jti":"{jti}"}}"#);
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

fn make_server() -> AuthorizationServer {
    let key = generate_signing_key(Alg::EdDSA).expect("key");
    AuthorizationServer::new(
        ServerConfig::new("https://auth.example", "api"),
        vec![Client {
            client_id: "spa".into(),
            redirect_uris: vec!["https://app.example/cb".into()],
        }],
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
            },
            now_token, None, "https://auth.example/token")
        .unwrap_or_else(|e| panic!("{case}: token: {e}"));
    let rt = first
        .refresh_token
        .clone()
        .expect("refresh_token on code exchange");

    match action {
        "revoke_access" => {
            assert!(srv
                .introspect(&first.access_token, oauth::TokenTypeHint::AccessToken, now_token)
                .unwrap()
                .active);
            srv.revoke(
                &first.access_token,
                oauth::TokenTypeHint::AccessToken,
                client_id,
                now_token,
            )
            .unwrap();
            assert!(!srv
                .introspect(&first.access_token, oauth::TokenTypeHint::AccessToken, now_token)
                .unwrap()
                .active);
            assert_eq!(
                srv.userinfo(&first.access_token, now_token, None, "https://auth.example/userinfo")
                    .unwrap_err()
                    .code(),
                "invalid_token"
            );
        }
        "revoke_refresh" => {
            srv.revoke(&rt, oauth::TokenTypeHint::RefreshToken, client_id, now_token)
                .unwrap();
            assert!(!srv
                .introspect(&rt, oauth::TokenTypeHint::RefreshToken, now_token)
                .unwrap()
                .active);
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
            },
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

    match action {
        "dpop_bind" => {
            let proof = make_dpop_proof(
                "POST",
                token_htu,
                now_token,
                "j-bind",
                &dpop_key.pkcs8,
                &dpop_key.public,
            );
            let tok = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "authorization_code".into(),
                        code: issued.code,
                        redirect_uri: redirect_uri.into(),
                        client_id: client_id.into(),
                        code_verifier: verifier.into(),
                        refresh_token: String::new(),
                    },
                    now_token,
                    Some(&proof),
                    token_htu,
                )
                .unwrap();
            assert_eq!(tok.token_type, string(expect, "token_type"));
            let proof2 = make_dpop_proof(
                "GET",
                userinfo_htu,
                now_token,
                "j-ui",
                &dpop_key.pkcs8,
                &dpop_key.public,
            );
            let info = srv
                .userinfo(&tok.access_token, now_token, Some(&proof2), userinfo_htu)
                .unwrap();
            assert_eq!(info.sub, string(steps, "subject"));
        }
        "dpop_bad_htu" => {
            let proof = make_dpop_proof(
                "POST",
                "https://auth.example/wrong",
                now_token,
                "j-bad",
                &dpop_key.pkcs8,
                &dpop_key.public,
            );
            let err = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "authorization_code".into(),
                        code: issued.code,
                        redirect_uri: redirect_uri.into(),
                        client_id: client_id.into(),
                        code_verifier: verifier.into(),
                        refresh_token: String::new(),
                    },
                    now_token,
                    Some(&proof),
                    token_htu,
                )
                .expect_err("bad htu");
            assert_eq!(err.code(), string(expect, "error"), "{case}");
        }
        "dpop_userinfo_missing" => {
            let proof = make_dpop_proof(
                "POST",
                token_htu,
                now_token,
                "j-miss",
                &dpop_key.pkcs8,
                &dpop_key.public,
            );
            let tok = srv
                .exchange_token(
                    &TokenRequest {
                        grant_type: "authorization_code".into(),
                        code: issued.code,
                        redirect_uri: redirect_uri.into(),
                        client_id: client_id.into(),
                        code_verifier: verifier.into(),
                        refresh_token: String::new(),
                    },
                    now_token,
                    Some(&proof),
                    token_htu,
                )
                .unwrap();
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
