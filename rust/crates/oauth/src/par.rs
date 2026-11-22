//! Pushed Authorization Requests (RFC 9126 / ADR 0009 B1).

use std::collections::HashMap;

use ring::rand::{SecureRandom, SystemRandom};

use crate::error::OAuthError;
use jose::b64url;

/// Default PAR lifetime in seconds.
pub const DEFAULT_PAR_TTL_SECS: i64 = 60;

pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Stored authorize parameters from a successful PAR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParRecord {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub response_type: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Default)]
pub struct ParStore {
    entries: HashMap<String, ParRecord>,
}

impl ParStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn random_id() -> Result<String, OAuthError> {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| OAuthError::ServerError)?;
        Ok(b64url::encode(&bytes))
    }

    /// Stores `record` and returns the full `request_uri` string.
    pub fn issue(&mut self, record: ParRecord) -> Result<String, OAuthError> {
        let id = Self::random_id()?;
        let uri = format!("{REQUEST_URI_PREFIX}{id}");
        self.entries.insert(id, record);
        Ok(uri)
    }

    /// Takes the PAR entry (single use).
    pub fn redeem(&mut self, request_uri: &str, now: i64) -> Result<ParRecord, OAuthError> {
        let id = request_uri
            .strip_prefix(REQUEST_URI_PREFIX)
            .ok_or(OAuthError::InvalidRequest)?;
        let record = self.entries.remove(id).ok_or(OAuthError::InvalidRequest)?;
        if now >= record.expires_at {
            return Err(OAuthError::InvalidRequest);
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(expires_at: i64) -> ParRecord {
        ParRecord {
            client_id: "spa".into(),
            redirect_uri: "https://app.example/cb".into(),
            code_challenge: "x".into(),
            code_challenge_method: "S256".into(),
            response_type: "code".into(),
            state: None,
            scope: None,
            nonce: None,
            expires_at,
        }
    }

    #[test]
    fn issue_and_redeem_once() {
        let mut store = ParStore::new();
        let uri = store.issue(sample(10_000)).unwrap();
        assert!(uri.starts_with(REQUEST_URI_PREFIX));
        store.redeem(&uri, 1_000).unwrap();
        assert!(store.redeem(&uri, 1_001).is_err());
    }
}
