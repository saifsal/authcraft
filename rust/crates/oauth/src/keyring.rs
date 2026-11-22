//! Signing keyring with grace-period verify keys (ADR 0008 B3).

use jose::alg::Alg;
use jose::b64url;
use jose::jwk::PublicKey;
use jose::signing::{self, SigningKey};

use crate::error::OAuthError;

/// Default how long a retired key stays in JWKS (seconds).
pub const DEFAULT_VERIFY_GRACE_SECS: i64 = 3600;

#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub pkcs8: Vec<u8>,
    pub public: PublicKey,
    /// When this key stops being published (`None` = current signing key).
    pub verify_until: Option<i64>,
}

#[derive(Debug)]
pub struct Keyring {
    /// Index 0 is always the current signing key.
    keys: Vec<KeyEntry>,
    pub verify_grace_secs: i64,
}

impl Keyring {
    pub fn from_signing_key(signing: SigningKey, verify_grace_secs: i64) -> Self {
        Self {
            keys: vec![KeyEntry {
                pkcs8: signing.pkcs8,
                public: signing.public,
                verify_until: None,
            }],
            verify_grace_secs,
        }
    }

    pub fn current(&self) -> &KeyEntry {
        &self.keys[0]
    }

    pub fn rotate(&mut self, now: i64) -> Result<(), OAuthError> {
        let new = signing::generate_signing_key(Alg::EdDSA).map_err(|_| OAuthError::ServerError)?;
        if let Some(prev) = self.keys.first_mut() {
            prev.verify_until = Some(now.saturating_add(self.verify_grace_secs));
        }
        self.keys.insert(
            0,
            KeyEntry {
                pkcs8: new.pkcs8,
                public: new.public,
                verify_until: None,
            },
        );
        self.prune(now);
        Ok(())
    }

    pub fn prune(&mut self, now: i64) {
        self.keys.retain(|k| match k.verify_until {
            None => true,
            Some(until) => until > now,
        });
        debug_assert!(!self.keys.is_empty());
    }

    pub fn jwks_document(&self, now: i64) -> String {
        let mut parts = Vec::new();
        for k in &self.keys {
            if let Some(until) = k.verify_until {
                if until <= now {
                    continue;
                }
            }
            parts.push(jwk_json(&k.public));
        }
        format!(r#"{{"keys":[{}]}}"#, parts.join(","))
    }
}

fn jwk_json(public: &PublicKey) -> String {
    let kid = public.thumbprint();
    match public {
        PublicKey::Ed25519 { x } => format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{kid}","alg":"EdDSA","use":"sig"}}"#,
            b64url::encode(x)
        ),
        PublicKey::P256 { x, y } => format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","kid":"{kid}","alg":"ES256","use":"sig"}}"#,
            b64url::encode(x),
            b64url::encode(y)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::signing::generate_signing_key;

    #[test]
    fn rotate_keeps_old_until_grace_expires() {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let mut ring = Keyring::from_signing_key(key, 100);
        let kid0 = ring.current().public.thumbprint();
        ring.rotate(1_000).unwrap();
        let kid1 = ring.current().public.thumbprint();
        assert_ne!(kid0, kid1);
        let doc = ring.jwks_document(1_000);
        assert!(doc.contains(&kid0));
        assert!(doc.contains(&kid1));
        ring.prune(1_101);
        let doc2 = ring.jwks_document(1_101);
        assert!(!doc2.contains(&kid0));
        assert!(doc2.contains(&kid1));
    }
}
