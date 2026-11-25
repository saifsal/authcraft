# ADR 0010: M5 authentication (passwords, TOTP, WebAuthn)

- **Status:** Accepted (amended as M5 slices land)
- **Date:** 2026-11-22

## Context

M1–M4 use a stub login that posts an arbitrary `subject`. RFC 9700 and a
real IdP need resource-owner authentication. M5 replaces the stub with
passwords, then optional second factors.

## Decision — B1: Argon2id passwords

1. In-memory `UserStore`: `username` → `{ subject, name?, email?, password_hash,
   totp?, webauthn_creds }`.
2. Passwords are hashed with **Argon2id** (`argon2` crate defaults: interactive
   m=19456, t=2, p=1). Stored as PHC strings.
3. `authenticate_password(username, password)` returns `LoginSubject` or
   `invalid_credentials`. Missing usernames and wrong passwords share that code
   (library still runs a verify against a dummy hash on miss).
4. HTTP `GET/POST /login` uses `username` + `password`. Failed login keeps the
   pending authorize ticket and re-renders the form.
5. Demo seeds user **`alice`** with published test password **`password`**
   (`oauth::DEMO_ALICE_PASSWORD`). Not for production.
6. Authorize/token/OIDC paths are unchanged once `LoginSubject` is obtained.

## Amendments

### B2 — TOTP

1. RFC 6238 TOTP: HMAC-SHA1, 6 digits, 30-second step, ±1 step skew.
   Attempt lockout and replay protection: [ADR 0022](0022-second-factor-throttling.md).
   Implemented in `oauth::totp` with `ring` (no external TOTP crate).
2. `enroll_totp(username, issuer)` stores a base32 secret and returns
   `secret_b32` + `otpauth_uri` once.
3. HTTP `POST /enroll/totp` requires username + password.
4. After password success, if any MFA is enrolled, HTTP redirects to
   `/login/mfa` and keeps the authorize ticket. `POST /login/mfa` with
   `code` must verify TOTP before `finish_authorize`.
5. Shared vectors under `testvectors/authn/` cover good TOTP, wrong code,
   and out-of-window skew.

### B3 — WebAuthn

1. Second-factor **security keys** via `webauthn-rs` (not passwordless /
   discoverable passkeys).
2. RP ID / origin come from `ServerConfig` (demo: `localhost` /
   `http://localhost:8089`).
3. HTTP: `POST /enroll/webauthn/start|finish` (password-gated start) and
   `POST /login/mfa/webauthn/start|finish` during MFA.
4. If both TOTP and WebAuthn are enrolled, **either** second factor satisfies
   MFA.
5. Soft-authenticator coverage via `webauthn-authenticator-rs` SoftPasskey
   (library + HTTP e2e); no browser CI required.

## Consequences

- Stub subject picker is removed.
- Profile claims (`name`, `email`) come from the user record, not the login form.
- Demo issuer uses `http://localhost:8089` so WebAuthn origin checks succeed.

## Alternatives considered

- **bcrypt / scrypt.** Rejected; Argon2id is the current default for new systems.
- **Passwordless-only WebAuthn.** Deferred; password remains the primary factor.
