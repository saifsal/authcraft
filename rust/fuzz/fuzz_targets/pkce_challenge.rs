#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = oauth::pkce::challenge_s256(s);
        let _ = oauth::pkce::validate_verifier(s);
    }
});
