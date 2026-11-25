//! Single sign-on sessions and login tickets (ADR 0026).
//!
//! After any successful sign-in, authcraft sets `authcraft_session`, so a
//! later authorization request from another relying party completes without
//! asking again. Sessions are keyed by the SHA-256 of a 256-bit random cookie
//! value, carry a CSRF token for state-changing forms, expire after
//! [`SESSION_SECS`], and live in memory (a restart signs everyone out).
//!
//! Login tickets (`authcraft_login`) tie a sign-in form to the authorization
//! request that started it, or to a standalone sign-in when there is none.
//! They expire after [`TICKET_SECS`] and are swept as new ones are issued
//! (threat-model R5).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oauth::{LoginSubject, PendingAuthorization};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

/// Absolute session lifetime.
pub const SESSION_SECS: i64 = 24 * 3600;
/// Login and MFA ticket lifetime.
pub const TICKET_SECS: i64 = 10 * 60;
/// Session cookie name.
pub const SESSION_COOKIE: &str = "authcraft_session";
/// Login ticket cookie name.
pub const TICKET_COOKIE: &str = "authcraft_login";

fn random_b64url<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    SystemRandom::new().fill(&mut bytes).expect("system RNG");
    jose::b64url::encode(&bytes)
}

fn hash(raw: &str) -> String {
    jose::b64url::encode(digest::digest(&digest::SHA256, raw.as_bytes()).as_ref())
}

/// A signed-in browser.
#[derive(Debug, Clone)]
pub struct Session {
    /// The identity issued to relying parties.
    pub login: LoginSubject,
    /// The local account, when the sign-in used one (not LDAP or upstream
    /// OIDC). Its profile is re-read on use.
    pub username: Option<String>,
    /// Token for state-changing forms (logout).
    pub csrf: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// In-memory session store. Clones share state.
#[derive(Clone, Default)]
pub struct Sessions {
    map: Arc<Mutex<HashMap<String, Session>>>,
}

impl Sessions {
    /// Starts a session; returns the raw cookie value.
    pub fn create(&self, login: LoginSubject, username: Option<String>, now: i64) -> String {
        let raw = random_b64url::<32>();
        let session = Session {
            login,
            username,
            csrf: random_b64url::<16>(),
            created_at: now,
            expires_at: now + SESSION_SECS,
        };
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, s| s.expires_at > now);
        map.insert(hash(&raw), session);
        raw
    }

    /// The live session for a raw cookie value.
    pub fn get(&self, raw: &str, now: i64) -> Option<Session> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&hash(raw)).filter(|s| s.expires_at > now).cloned()
    }

    /// Ends one session.
    pub fn remove(&self, raw: &str) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&hash(raw));
    }

    /// Ends every session of a local account (after a password reset).
    pub fn revoke_user(&self, username: &str) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, s| s.username.as_deref() != Some(username));
    }
}

/// A sign-in in progress.
#[derive(Debug, Clone)]
pub struct LoginTicket {
    /// The authorization request to finish, or `None` for a standalone
    /// sign-in (which ends at `/account`).
    pub pending: Option<PendingAuthorization>,
    /// Where a standalone sign-in returns to (a local path).
    pub return_to: Option<String>,
    pub created_at: i64,
}

/// Expiring map of tickets. Clones share state.
#[derive(Clone)]
pub struct Tickets<T: Clone> {
    map: Arc<Mutex<HashMap<String, (T, i64)>>>,
}

impl<T: Clone> Default for Tickets<T> {
    fn default() -> Self {
        Self {
            map: Arc::default(),
        }
    }
}

impl<T: Clone> Tickets<T> {
    /// Stores `value` under a fresh ticket, sweeping expired ones.
    pub fn issue(&self, value: T, now: i64) -> String {
        let ticket = random_b64url::<16>();
        self.put(ticket.clone(), value, now);
        ticket
    }

    /// Stores `value` under an existing ticket name.
    pub fn put(&self, ticket: String, value: T, now: i64) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (_, at)| now - *at < TICKET_SECS);
        map.insert(ticket, (value, now));
    }

    /// The value for a live ticket.
    pub fn get(&self, ticket: &str, now: i64) -> Option<T> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(ticket)
            .filter(|(_, at)| now - *at < TICKET_SECS)
            .map(|(v, _)| v.clone())
    }

    /// Removes and returns the value for a live ticket.
    pub fn take(&self, ticket: &str, now: i64) -> Option<T> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(ticket)
            .filter(|(_, at)| now - *at < TICKET_SECS)
            .map(|(v, _)| v)
    }

    /// Removes a ticket.
    pub fn remove(&self, ticket: &str) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(ticket);
    }

    /// Number of stored tickets (tests).
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether no tickets are stored (tests).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The value of cookie `name` in a `Cookie` header.
pub fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        part.trim()
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .map(str::to_owned)
    })
}

/// A `Set-Cookie` value: HttpOnly, SameSite=Lax, Path=/, optional Secure.
pub fn set_cookie(name: &str, value: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_expire_and_revoke_by_user() {
        let s = Sessions::default();
        let raw = s.create(LoginSubject::new("sub-1"), Some("a@example.com".into()), 1_000);
        assert!(s.get(&raw, 1_001).is_some());
        assert!(s.get(&raw, 1_000 + SESSION_SECS).is_none(), "expired");
        let raw2 = s.create(LoginSubject::new("sub-1"), Some("a@example.com".into()), 2_000);
        s.revoke_user("a@example.com");
        assert!(s.get(&raw2, 2_001).is_none());
        assert!(s.get("unknown", 2_001).is_none());
    }

    #[test]
    fn tickets_expire_and_are_swept() {
        let t: Tickets<u8> = Tickets::default();
        let old = t.issue(1, 0);
        assert_eq!(t.get(&old, TICKET_SECS - 1), Some(1));
        assert_eq!(t.get(&old, TICKET_SECS), None);
        t.issue(2, TICKET_SECS + 1);
        assert_eq!(t.len(), 1, "issuing swept the expired ticket");
        let fresh = t.issue(3, TICKET_SECS + 2);
        assert_eq!(t.take(&fresh, TICKET_SECS + 3), Some(3));
        assert_eq!(t.take(&fresh, TICKET_SECS + 3), None, "single use");
    }

    #[test]
    fn cookie_parsing_matches_exact_names() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "authcraft_login_x=bad; authcraft_login=good; other=1".parse().unwrap(),
        );
        assert_eq!(cookie_value(&h, TICKET_COOKIE).as_deref(), Some("good"));
        assert_eq!(cookie_value(&h, SESSION_COOKIE), None);
    }
}
