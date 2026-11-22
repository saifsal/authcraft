# M1 OAuth authorization code + PKCE

This note tracks the first OAuth slice. Profile decisions are locked in
[ADR 0005](adr/0005-oauth-code-pkce.md). Access tokens are compact `at+jwt`
values verified by the M0 JOSE stack.

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

## Not in M1

Refresh tokens, confidential clients, real authentication, OIDC, PAR/DPoP, and
cross-language OAuth vectors. See the roadmap in `README.md`.
