//! Opaque refresh tokens with family rotation (ADR 0008 B1).

use std::collections::{HashMap, HashSet};

use ring::rand::{SecureRandom, SystemRandom};

use crate::error::OAuthError;
use jose::b64url;

/// Default refresh-token lifetime in seconds.
pub const DEFAULT_REFRESH_TOKEN_TTL_SECS: i64 = 86_400;

#[derive(Debug, Clone)]
pub struct RefreshRecord {
    pub family_id: String,
    pub client_id: String,
    pub subject: String,
    pub scope: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub expires_at: i64,
    /// When set, refresh requires a matching DPoP proof (RFC 9449 / ADR 0009 B4).
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Default)]
pub struct RefreshStore {
    active: HashMap<String, RefreshRecord>,
    /// Consumed token → family id (reuse detection).
    consumed: HashMap<String, String>,
    revoked_families: HashSet<String>,
}

impl RefreshStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn random_token() -> Result<String, OAuthError> {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| OAuthError::ServerError)?;
        Ok(b64url::encode(&bytes))
    }

    /// Issues the first refresh token for a new family.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_new_family(
        &mut self,
        client_id: String,
        subject: String,
        scope: Option<String>,
        name: Option<String>,
        email: Option<String>,
        expires_at: i64,
        dpop_jkt: Option<String>,
    ) -> Result<String, OAuthError> {
        let family_id = Self::random_token()?;
        let token = Self::random_token()?;
        self.active.insert(
            token.clone(),
            RefreshRecord {
                family_id,
                client_id,
                subject,
                scope,
                name,
                email,
                expires_at,
                dpop_jkt,
            },
        );
        Ok(token)
    }

    /// Rotates: consume `presented`, return `(new_token, record)`.
    /// Reuse of a consumed token revokes the family and returns `InvalidGrant`.
    pub fn rotate(
        &mut self,
        presented: &str,
        client_id: &str,
        now: i64,
        new_expires_at: i64,
    ) -> Result<(String, RefreshRecord), OAuthError> {
        if let Some(family_id) = self.consumed.get(presented).cloned() {
            self.revoke_family(&family_id);
            return Err(OAuthError::InvalidGrant);
        }

        let record = self
            .active
            .remove(presented)
            .ok_or(OAuthError::InvalidGrant)?;
        self.consumed
            .insert(presented.to_owned(), record.family_id.clone());

        if self.revoked_families.contains(&record.family_id) {
            return Err(OAuthError::InvalidGrant);
        }
        if record.client_id != client_id || now >= record.expires_at {
            self.revoke_family(&record.family_id);
            return Err(OAuthError::InvalidGrant);
        }

        let new_token = Self::random_token()?;
        let mut next = record.clone();
        next.expires_at = new_expires_at;
        self.active.insert(new_token.clone(), next.clone());
        Ok((new_token, next))
    }

    /// Revokes all active tokens in a family.
    pub fn revoke_family(&mut self, family_id: &str) {
        self.revoked_families.insert(family_id.to_owned());
        self.active.retain(|_, r| r.family_id != family_id);
    }

    pub fn get_active(&self, token: &str) -> Option<&RefreshRecord> {
        self.active.get(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_then_reuse_revokes_family() {
        let mut store = RefreshStore::new();
        let first = store
            .issue_new_family(
                "spa".into(),
                "alice".into(),
                Some("read".into()),
                None,
                None,
                10_000,
                None,
            )
            .unwrap();
        let (second, _) = store.rotate(&first, "spa", 1_000, 10_000).unwrap();
        assert!(store.rotate(&first, "spa", 1_001, 10_000).is_err());
        assert!(store.rotate(&second, "spa", 1_002, 10_000).is_err());
    }

    #[test]
    fn dpop_jkt_survives_rotation() {
        let mut store = RefreshStore::new();
        let first = store
            .issue_new_family(
                "spa".into(),
                "alice".into(),
                None,
                None,
                None,
                10_000,
                Some("jkt-abc".into()),
            )
            .unwrap();
        let (second, rec) = store.rotate(&first, "spa", 1_000, 10_000).unwrap();
        assert_eq!(rec.dpop_jkt.as_deref(), Some("jkt-abc"));
        assert_eq!(
            store.get_active(&second).and_then(|r| r.dpop_jkt.as_deref()),
            Some("jkt-abc")
        );
    }
}
