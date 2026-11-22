//! In-memory resource-owner accounts (ADR 0010).

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use ring::rand::{SecureRandom, SystemRandom};

use uuid::Uuid;
use webauthn_rs::prelude::SecurityKey;

use crate::server::LoginSubject;

/// Published demo password for seeded user `alice` (educational only).
pub const DEMO_ALICE_PASSWORD: &str = "password";

/// Stable UUID for demo user `alice` (WebAuthn user handle).
pub const DEMO_ALICE_UUID: Uuid = Uuid::from_bytes([
    0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0x41, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
]);

/// Authentication failure codes for password / MFA (ADR 0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthnError {
    InvalidCredentials,
    MfaRequired,
    InvalidMfa,
}

impl AuthnError {
    pub fn code(self) -> &'static str {
        match self {
            AuthnError::InvalidCredentials => "invalid_credentials",
            AuthnError::MfaRequired => "mfa_required",
            AuthnError::InvalidMfa => "invalid_mfa",
        }
    }
}

impl fmt::Display for AuthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for AuthnError {}

/// Stored account record.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub subject: String,
    pub user_handle: Uuid,
    pub name: Option<String>,
    pub email: Option<String>,
    /// PHC-encoded Argon2id hash.
    pub password_hash: String,
    /// TOTP secret (base32) when enrolled.
    pub totp_secret: Option<String>,
    /// WebAuthn security-key credentials (second factor).
    pub webauthn_credentials: Vec<SecurityKey>,
}

impl UserRecord {
    pub fn login_subject(&self) -> LoginSubject {
        LoginSubject {
            subject: self.subject.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
        }
    }

    pub fn mfa_enrolled(&self) -> bool {
        self.totp_secret.is_some() || !self.webauthn_credentials.is_empty()
    }

    pub fn webauthn_enrolled(&self) -> bool {
        !self.webauthn_credentials.is_empty()
    }
}

/// Username → account map.
#[derive(Debug, Default)]
pub struct UserStore {
    users: HashMap<String, UserRecord>,
}

impl UserStore {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    pub fn insert(&mut self, username: impl Into<String>, record: UserRecord) {
        self.users.insert(username.into(), record);
    }

    pub fn get(&self, username: &str) -> Option<&UserRecord> {
        self.users.get(username)
    }

    pub fn get_mut(&mut self, username: &str) -> Option<&mut UserRecord> {
        self.users.get_mut(username)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &UserRecord)> {
        self.users.iter()
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    pub fn remove(&mut self, username: &str) -> Option<UserRecord> {
        self.users.remove(username)
    }

    pub fn username_for_handle(&self, id: Uuid) -> Option<&str> {
        self.users
            .iter()
            .find(|(_, u)| u.user_handle == id)
            .map(|(name, _)| name.as_str())
    }

    pub fn get_by_handle(&self, id: Uuid) -> Option<(&str, &UserRecord)> {
        self.users
            .iter()
            .find(|(_, u)| u.user_handle == id)
            .map(|(name, u)| (name.as_str(), u))
    }

    /// Seeds demo user `alice` with [`DEMO_ALICE_PASSWORD`].
    pub fn seed_demo_alice(&mut self) {
        let hash = hash_password(DEMO_ALICE_PASSWORD).expect("hash demo password");
        self.insert(
            "alice",
            UserRecord {
                subject: "alice".into(),
                user_handle: DEMO_ALICE_UUID,
                name: Some("Alice".into()),
                email: Some("alice@example.com".into()),
                password_hash: hash,
                totp_secret: None,
                webauthn_credentials: Vec::new(),
            },
        );
    }
}

/// Argon2id with the crate's default interactive parameters (m=19456, t=2, p=1).
pub fn hash_password(password: &str) -> Result<String, AuthnError> {
    let mut salt_bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut salt_bytes)
        .map_err(|_| AuthnError::InvalidCredentials)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AuthnError::InvalidCredentials)?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthnError::InvalidCredentials)?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<(), AuthnError> {
    let parsed = PasswordHash::new(password_hash).map_err(|_| AuthnError::InvalidCredentials)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AuthnError::InvalidCredentials)
}

impl UserStore {
    pub fn authenticate_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LoginSubject, AuthnError> {
        let Some(user) = self.get(username.trim()) else {
            // Same failure as a bad password (no username oracle in the library API).
            let _ = verify_password(password, dummy_hash());
            return Err(AuthnError::InvalidCredentials);
        };
        verify_password(password, &user.password_hash)?;
        Ok(user.login_subject())
    }

    pub fn set_totp_secret(&mut self, username: &str, secret_b32: String) -> Result<(), AuthnError> {
        let user = self
            .get_mut(username.trim())
            .ok_or(AuthnError::InvalidCredentials)?;
        user.totp_secret = Some(secret_b32);
        Ok(())
    }

    pub fn totp_secret(&self, username: &str) -> Option<String> {
        self.get(username.trim())
            .and_then(|u| u.totp_secret.clone())
    }
}

fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password("authcraft-dummy-user").expect("dummy hash"))
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_password() {
        let hash = hash_password("secret").unwrap();
        verify_password("secret", &hash).unwrap();
        assert!(verify_password("wrong", &hash).is_err());
    }

    #[test]
    fn demo_alice_authenticates() {
        let mut store = UserStore::new();
        store.seed_demo_alice();
        let login = store
            .authenticate_password("alice", DEMO_ALICE_PASSWORD)
            .unwrap();
        assert_eq!(login.subject, "alice");
        assert_eq!(login.name.as_deref(), Some("Alice"));
        assert!(store
            .authenticate_password("alice", "wrong")
            .is_err());
        assert!(store
            .authenticate_password("nobody", DEMO_ALICE_PASSWORD)
            .is_err());
    }
}
