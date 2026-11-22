//! LDAP-style directory bind gateway (ADR 0012 B2).
//!
//! CI uses [`MemoryDirectory`]; a real `ldap3` binder can implement [`DirectoryBind`] later.

use std::collections::HashMap;

use crate::server::LoginSubject;
use crate::users::{hash_password, verify_password, AuthnError};

/// Directory bind authentication (username/password → subject).
pub trait DirectoryBind: Send + Sync {
    fn authenticate(&self, username: &str, password: &str) -> Result<LoginSubject, AuthnError>;
}

/// Seeded in-memory directory for demos and tests.
#[derive(Debug, Default)]
pub struct MemoryDirectory {
    users: HashMap<String, MemoryDirectoryUser>,
}

#[derive(Debug, Clone)]
pub struct MemoryDirectoryUser {
    pub subject: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub password_hash: String,
}

impl MemoryDirectory {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    pub fn insert(&mut self, username: impl Into<String>, user: MemoryDirectoryUser) {
        self.users.insert(username.into(), user);
    }

    /// Seed a user with an Argon2id password.
    pub fn seed(
        &mut self,
        username: &str,
        password: &str,
        subject: &str,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Result<(), AuthnError> {
        let password_hash = hash_password(password)?;
        self.insert(
            username,
            MemoryDirectoryUser {
                subject: subject.into(),
                name: name.map(str::to_owned),
                email: email.map(str::to_owned),
                password_hash,
            },
        );
        Ok(())
    }
}

impl DirectoryBind for MemoryDirectory {
    fn authenticate(&self, username: &str, password: &str) -> Result<LoginSubject, AuthnError> {
        let Some(user) = self.users.get(username.trim()) else {
            let _ = verify_password(password, &dummy_hash());
            return Err(AuthnError::InvalidCredentials);
        };
        verify_password(password, &user.password_hash)?;
        Ok(LoginSubject {
            subject: user.subject.clone(),
            name: user.name.clone(),
            email: user.email.clone(),
        })
    }
}

fn dummy_hash() -> String {
    use std::sync::OnceLock;
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password("ldap-dummy").expect("hash"))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_directory_authenticates() {
        let mut dir = MemoryDirectory::new();
        dir.seed("ldapuser", "ldap-pass", "ldap-sub", Some("Ldap"), None)
            .unwrap();
        let login = dir.authenticate("ldapuser", "ldap-pass").unwrap();
        assert_eq!(login.subject, "ldap-sub");
        assert!(dir.authenticate("ldapuser", "wrong").is_err());
    }
}
