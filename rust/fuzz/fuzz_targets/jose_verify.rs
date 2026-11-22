#![no_main]
use jose::alg::Alg;
use jose::jwks::Jwks;
use jose::verify::{self, Policy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let jwks = Jwks::parse(br#"{"keys":[]}"#).expect("empty jwks");
    let _ = verify::verify(
        data,
        &jwks,
        &Policy {
            algorithms: vec![Alg::EdDSA, Alg::ES256, Alg::HS256],
            issuer: Some("https://fuzz.example".into()),
            audience: Some("fuzz".into()),
            now: 1_700_000_000,
            leeway: 60,
            typ: None,
            max_token_bytes: 8192,
        },
    );
});
