//! One-time authorization codes (ADR 0005 / ADR 0006).

use std::collections::HashMap;

use ring::rand::{SecureRandom, SystemRandom};

use crate::error::OAuthError;
use jose::b64url;

/// Default authorization-code lifetime in seconds.
pub const DEFAULT_CODE_TTL_SECS: i64 = 60;

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub subject: String,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub expires_at: i64,
}

/// In-memory single-use code store.
#[derive(Debug, Default)]
pub struct CodeStore {
    codes: HashMap<String, AuthorizationCode>,
}

impl CodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a new opaque code and stores the binding.
    pub fn issue(&mut self, record: AuthorizationCode) -> Result<String, OAuthError> {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| OAuthError::ServerError)?;
        let code = b64url::encode(&bytes);
        self.codes.insert(code.clone(), record);
        Ok(code)
    }

    /// Takes the code (single use). Returns `invalid_grant` if missing or expired.
    pub fn redeem(&mut self, code: &str, now: i64) -> Result<AuthorizationCode, OAuthError> {
        let record = self.codes.remove(code).ok_or(OAuthError::InvalidGrant)?;
        if now >= record.expires_at {
            return Err(OAuthError::InvalidGrant);
        }
        Ok(record)
    }
}
