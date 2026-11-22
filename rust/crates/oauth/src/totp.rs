//! RFC 6238 TOTP (SHA-1, 6 digits, 30s step) for M5 MFA (ADR 0010).

use ring::hmac;

use crate::users::AuthnError;

pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_STEP_SECS: i64 = 30;
pub const TOTP_SKEW_STEPS: i64 = 1;
const SECRET_BYTES: usize = 20;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generate a 160-bit TOTP shared secret.
pub fn generate_secret() -> Result<[u8; SECRET_BYTES], AuthnError> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut secret = [0u8; SECRET_BYTES];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| AuthnError::InvalidCredentials)?;
    Ok(secret)
}

/// Unpadded base32 (RFC 4648) encode.
pub fn encode_base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(B32[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(B32[idx] as char);
    }
    out
}

/// Decode unpadded base32; rejects non-alphabet input.
pub fn decode_base32(s: &str) -> Result<Vec<u8>, AuthnError> {
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in s.chars() {
        let upper = c.to_ascii_uppercase();
        let val = match upper {
            'A'..='Z' => (upper as u8) - b'A',
            '2'..='7' => (upper as u8) - b'2' + 26,
            '=' => continue,
            _ => return Err(AuthnError::InvalidMfa),
        };
        buffer = (buffer << 5) | u64::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mut msg = [0u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());
    let tag = hmac::sign(&key, &msg);
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    bin % 10u32.pow(TOTP_DIGITS)
}

/// Compute the TOTP code for `now` (Unix seconds).
pub fn generate_code(secret: &[u8], now: i64) -> String {
    let counter = (now / TOTP_STEP_SECS) as u64;
    format!("{:0width$}", hotp(secret, counter), width = TOTP_DIGITS as usize)
}

/// Verify a user-supplied code with ±[`TOTP_SKEW_STEPS`] window.
pub fn verify_code(secret: &[u8], code: &str, now: i64) -> bool {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let center = now / TOTP_STEP_SECS;
    for delta in -TOTP_SKEW_STEPS..=TOTP_SKEW_STEPS {
        let counter = (center + delta) as u64;
        let expected = format!("{:0width$}", hotp(secret, counter), width = TOTP_DIGITS as usize);
        if constant_eq(code.as_bytes(), expected.as_bytes()) {
            return true;
        }
    }
    false
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECS}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_8digit_reference_truncated_to_6() {
        // RFC 6238 Appendix B uses 8-digit; we only ship 6-digit codes.
        let secret = b"12345678901234567890";
        let code = generate_code(secret, 59);
        assert_eq!(code.len(), 6);
        assert!(verify_code(secret, &code, 59));
        assert!(!verify_code(secret, "000000", 59));
    }

    #[test]
    fn base32_round_trip() {
        let secret = generate_secret().unwrap();
        let b32 = encode_base32(&secret);
        let back = decode_base32(&b32).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn skew_window_accepts_adjacent_step() {
        let secret = b"12345678901234567890";
        let code = generate_code(secret, 90);
        assert!(verify_code(secret, &code, 90 + TOTP_STEP_SECS));
        assert!(!verify_code(
            secret,
            &code,
            90 + TOTP_STEP_SECS * (TOTP_SKEW_STEPS + 2)
        ));
    }
}
