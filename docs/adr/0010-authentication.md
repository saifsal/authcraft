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

### B2 — TOTP (pending)

### B3 — WebAuthn (pending)

## Consequences

- Stub subject picker is removed.
- Profile claims (`name`, `email`) come from the user record, not the login form.
- TOTP and WebAuthn fields exist on the record but are unused until B2/B3.

## Alternatives considered

- **bcrypt / scrypt.** Rejected; Argon2id is the current default for new systems.
- **Passwordless-only.** Deferred; password remains the primary factor for this slice.
