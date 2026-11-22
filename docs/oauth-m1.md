# M1 OAuth authorization code + PKCE

**Status: complete.** Profile decisions are locked in
[ADR 0005](adr/0005-oauth-code-pkce.md). Access tokens are compact `at+jwt`
values verified by the M0 JOSE stack. OpenID Connect on the same flow is M2
([ADR 0006](adr/0006-oidc-core-code.md), [oauth-m2.md](oauth-m2.md)).

## What exists

| Piece | Location |
|---|---|
| Library (PKCE S256, codes, token mint) | `rust/crates/oauth` |
| HTTP binder (Axum) | `rust/crates/oauth-http` |
| Protocol vectors | `testvectors/oauth/` |
| ADR | `docs/adr/0005-oauth-code-pkce.md` |

## Run locally

From `rust/`:

```bash
cargo test -p oauth
cargo test -p oauth-http
cargo run -p oauth-http
```

The demo listens on `http://127.0.0.1:8089` with a stub `/login`, ephemeral
Ed25519 signing key, and a public client `spa` (redirect
`http://127.0.0.1:9999/cb` and `https://app.example/cb`).

## Deferred past M1

Refresh tokens (M3), confidential clients, real authentication (M5), PAR/DPoP
(M4), and cross-language OAuth vectors. OIDC shipped in M2 on the same crates.
