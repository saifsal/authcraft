# ADR 0026: Single sign-on sessions, logout, and ticket expiry

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Every authorization request asked for a password, even right after a
sign-in. For M9, authcraft is the common login for tacto and glossa:
signing in once should carry over to the second app. People also need to
sign in at `authcraft.accumu.cc` directly to see their account. Login and
MFA tickets never expired (threat-model R5).

## Decision

1. **SSO session.** Every successful sign-in (password, with or without
   TOTP / WebAuthn, LDAP, upstream OIDC) goes through one function,
   `complete_login`, which starts a session and sets `authcraft_session`
   (`HttpOnly`, `SameSite=Lax`, `Secure` under HTTPS or `--secure-cookies`,
   24 h). The cookie holds 256 random bits; the store keeps its SHA-256.
   Sessions are in memory: a restart signs everyone out.
2. **Using the session.** `/authorize` with a live session issues the code at
   once. For a local account the profile is re-read on each use, and the
   session is dropped if the account is gone or unverified.
   - `prompt=login` ignores the session and asks again.
   - `prompt=none` without a session redirects `error=login_required` (with
     `state` and RFC 9207 `iss`) to the validated redirect URI (OIDC Core
     §3.1.2.6). Other `prompt` values are ignored.
3. **Standalone sign-in.** `GET /login` without a live ticket issues one with
   no pending authorization request; after sign-in the browser goes to
   `/account`, or to `return_to` if that is a local path (no scheme, no
   `//`, no backslash), so it cannot become an open redirect.
4. **Account page.** `/account` shows the name, email, the `sub` relying
   parties see, and the second-factor status, with a sign-out button.
5. **Logout.** `POST /logout` needs the session's CSRF token (constant-time
   comparison); `GET /logout` only shows the form. Relying-party sessions are
   not ended (no back-channel or RP-initiated logout in this slice).
6. **Password reset** ends every session of that account.
7. **Tickets.** Login and MFA tickets expire after 10 minutes and are swept
   whenever a new one is issued (closes threat-model R5).

## Consequences

- Tests: `session` unit tests and `tests/sso.rs` (session reuse,
  `prompt=login`, `prompt=none`, standalone sign-in, `return_to` hardening,
  CSRF on logout, reset ends sessions).
- `auth_time` and `max_age` are not implemented yet.
