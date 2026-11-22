//! Runs `testvectors/oauth/` against the oauth library (ADR 0005).

use std::fs;
use std::path::{Path, PathBuf};

use jose::alg::Alg;
use jose::json::{self, Value};
use jose::jwks::Jwks;
use jose::signing::generate_signing_key;
use jose::verify::{self, Policy};
use oauth::pkce;
use oauth::{
    AuthorizationServer, AuthorizeRequest, Client, ServerConfig, TokenRequest,
};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors/oauth")
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

fn run_vector(path: &Path) {
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
    });

    let phase = optional_string(expect, "phase").unwrap_or(if ok { "token" } else { "authorize" });

    if !ok && phase == "authorize" {
        let err = begin.expect_err("expected authorize failure");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
        return;
    }

    let pending = begin.unwrap_or_else(|e| panic!("{case}: authorize failed: {e}"));
    let issued = srv
        .finish_authorize(pending, subject, now_auth)
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
    };

    let first = srv.exchange_token(&req, now_token);
    if bool_field(steps, "replay_token") {
        first.unwrap_or_else(|e| panic!("{case}: first token: {e}"));
        let second = srv.exchange_token(&req, now_token + 1);
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
    } else {
        let err = first.expect_err("expected token failure");
        assert_eq!(err.code(), string(expect, "error"), "{case}");
    }
}

#[test]
fn oauth_shared_vectors() {
    let dir = vectors_dir();
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json") && p.file_name() != Some("schema.json".as_ref()))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no oauth vectors");
    for f in files {
        run_vector(&f);
    }
}
