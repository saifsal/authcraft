# M5 authentication

**Status: in progress** (B1 passwords landed; TOTP and WebAuthn next).
Profile: [ADR 0010](adr/0010-authentication.md).

## B1 — Argon2id passwords

`UserStore` + `authenticate_password`. Demo user `alice` / `password`.
HTTP `/login` posts `username` and `password`.
Vectors: `testvectors/authn/`.

## Run

```bash
cargo test -p oauth --test vectors
cargo test -p oauth-http
```
