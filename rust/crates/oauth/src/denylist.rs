//! Access-token `jti` denylist until expiry (ADR 0008 B2).

use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct JtiDenylist {
    /// jti → exp (Unix seconds)
    entries: HashMap<String, i64>,
}

impl JtiDenylist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, jti: String, exp: i64) {
        self.entries.insert(jti, exp);
    }

    pub fn is_revoked(&mut self, jti: &str, now: i64) -> bool {
        self.prune(now);
        self.entries.contains_key(jti)
    }

    pub fn prune(&mut self, now: i64) {
        self.entries.retain(|_, exp| *exp > now);
    }
}
