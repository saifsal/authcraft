# M5 authentication

**Status: complete** for the passwords + TOTP + WebAuthn second-factor slice.
Profile: [ADR 0010](adr/0010-authentication.md).

## B1 — Argon2id passwords

`UserStore` + `authenticate_password`. Demo user `alice` / `password`.
HTTP `/login` posts `username` and `password`.
Vectors: `testvectors/authn/`.

## B2 — TOTP

`POST /enroll/totp` (username + password) returns `secret` + `otpauth_uri`.
When enrolled, `/login` redirects to `/login/mfa` for a TOTP code.

## B3 — WebAuthn

Security-key second factor (`webauthn-rs`):
- `POST /enroll/webauthn/start` + `/finish`
- `POST /login/mfa/webauthn/start` + `/finish`
Demo RP origin is `http://localhost:8089`.

## Run

```bash
cargo test -p oauth --test vectors
cargo test -p oauth-http
```
