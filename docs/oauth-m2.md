# M2 OpenID Connect (authorization code)

**Status: complete.** Profile decisions are locked in
[ADR 0006](adr/0006-oidc-core-code.md). This slice builds on M1 OAuth code +
PKCE ([ADR 0005](adr/0005-oauth-code-pkce.md)). Token lifecycle (refresh,
revocation) is M3.

## What exists

| Piece | Location |
|---|---|
| ID token + `at_hash` + UserInfo library APIs | `rust/crates/oauth` (`id_token`, `server`) |
| Discovery + `/userinfo` HTTP | `rust/crates/oauth-http` |
| Protocol vectors | `testvectors/oidc/` |
| ADR | `docs/adr/0006-oidc-core-code.md` |

## Run locally

From `rust/`:

```bash
cargo test -p oauth
cargo test -p oauth-http
cargo run -p oauth-http
```

OIDC demo: authorize with `scope=openid` and a `nonce`, complete stub login,
exchange the code, then call `/userinfo` with the access token. Discovery is at
`/.well-known/openid-configuration`.

## Deferred past M2

Hybrid/implicit, RP logout, `claims` request objects, confidential clients, and
cross-language OIDC vectors. Refresh tokens ship in M3.
