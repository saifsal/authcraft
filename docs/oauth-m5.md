# M5 authentication

**Status: in progress** (B1 passwords + B2 TOTP landed; WebAuthn next).
Profile: [ADR 0010](adr/0010-authentication.md).

## B1 — Argon2id passwords

`UserStore` + `authenticate_password`. Demo user `alice` / `password`.
HTTP `/login` posts `username` and `password`.
Vectors: `testvectors/authn/`.

## B2 — TOTP

`POST /enroll/totp` (username + password) returns `secret` + `otpauth_uri`.
When enrolled, `/login` redirects to `/login/mfa` for a TOTP code.

## Run

```bash
cargo test -p oauth --test vectors
cargo test -p oauth-http
```
