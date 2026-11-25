//! Fixed-window rate limiting (ADR 0025), ported from glossa.
//!
//! In production the server listens on loopback behind Caddy, which replaces
//! any client-supplied `X-Forwarded-For` with the peer address, so the last
//! entry of that header is the client. Requests without it (demo, tests)
//! share the `"local"` bucket.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

/// Entries kept before expired windows are swept.
const SWEEP_AT: usize = 4_096;

/// Counts events per key in fixed windows. Clones share the counts.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    keys: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit: limit.max(1),
            window,
            keys: Arc::default(),
        }
    }

    /// Counts one event for `key`; `false` when it is over the limit.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if keys.len() >= SWEEP_AT {
            let window = self.window;
            keys.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = keys.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.limit
    }

    /// Whether `key` is still under the limit, without counting an event.
    pub fn peek(&self, key: &str) -> bool {
        let now = Instant::now();
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        match keys.get(key) {
            Some((start, count)) if now.duration_since(*start) < self.window => *count < self.limit,
            _ => true,
        }
    }

    /// Forgets `key` (after a successful login, for example).
    pub fn reset(&self, key: &str) {
        self.keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }
}

/// The client address Caddy forwarded, or `"local"` when there is none.
pub fn client_key(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("local")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_key_and_resets() {
        let l = RateLimiter::new(2, Duration::from_secs(60));
        assert!(l.allow("a") && l.allow("a"));
        assert!(!l.allow("a"));
        assert!(!l.peek("a"));
        assert!(l.allow("b"));
        l.reset("a");
        assert!(l.peek("a") && l.allow("a"));
    }

    #[test]
    fn client_key_uses_last_forwarded_entry() {
        let mut h = HeaderMap::new();
        assert_eq!(client_key(&h), "local");
        h.insert("x-forwarded-for", "198.51.100.1, 203.0.113.9".parse().unwrap());
        assert_eq!(client_key(&h), "203.0.113.9");
    }
}
