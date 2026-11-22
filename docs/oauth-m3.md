# M3 token lifecycle

**Status: complete** for the B1–B3 slice. Profile:
[ADR 0008](adr/0008-token-lifecycle.md).

## B1 — rotating refresh tokens

Opaque `refresh_token` on code exchange; rotation; reuse revokes the family.
Access tokens carry `jti`. Vectors under `testvectors/token/`.

## B2 — revoke + introspect

`POST /revoke` and `POST /introspect`. Access revoke denylists `jti`; refresh
revoke kills the family. UserInfo rejects denylisted tokens.

## B3 — signing key rotation

`AuthorizationServer::rotate_signing_key(now)` advances the signer; previous
keys stay in JWKS for `verify_grace_secs` (default 3600). No public rotate
HTTP route.

## Run

```bash
cargo test -p oauth
cargo test -p oauth-http
```
