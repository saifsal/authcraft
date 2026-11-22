//! Stable-toolchain garbage-input smoke (ADR 0013 B2 companion).
//!
//! Complements cargo-fuzz targets: parsers must not panic on arbitrary bytes.

use jose::alg::Alg;
use jose::b64url;
use jose::json;
use jose::jwks::Jwks;
use jose::verify::{self, Policy};

fn policy() -> Policy {
    Policy {
        algorithms: vec![Alg::EdDSA, Alg::ES256, Alg::HS256],
        issuer: Some("https://smoke.example".into()),
        audience: Some("smoke".into()),
        now: 1_700_000_000,
        leeway: 0,
        typ: None,
        max_token_bytes: 4096,
    }
}

#[test]
fn garbage_does_not_panic() {
    let samples: &[&[u8]] = &[
        b"",
        b"@",
        b"====",
        b"{",
        b"{\"a\":1,\"a\":2}",
        b"a.b",
        b"a.b.c.d",
        b"../../../etc/passwd",
        &[0xff, 0xfe, 0x00, 0x01],
        &vec![b'A'; 10_000],
    ];
    let jwks = Jwks::parse(br#"{"keys":[]}"#).unwrap();
    for sample in samples {
        if let Ok(s) = std::str::from_utf8(sample) {
            let _ = b64url::decode(s);
        }
        let _ = json::parse(sample);
        let _ = Jwks::parse(sample);
        let _ = verify::verify(sample, &jwks, &policy());
    }
}

#[test]
fn deterministic_prng_bytes_do_not_panic() {
    // xorshift-ish walk without depending on rand.
    let mut x: u64 = 0x1234_5678_9abc_def0;
    let mut buf = [0u8; 256];
    let jwks = Jwks::parse(br#"{"keys":[]}"#).unwrap();
    for _ in 0..200 {
        for b in &mut buf {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        if let Ok(s) = std::str::from_utf8(&buf) {
            let _ = b64url::decode(s);
        }
        let _ = json::parse(&buf);
        let _ = verify::verify(&buf, &jwks, &policy());
    }
}
