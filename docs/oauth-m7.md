# M7 federation

**Status: complete** for the OIDC RP + LDAP MemoryDirectory slice.
Profile: [ADR 0012](adr/0012-federation.md).

## B1 — OIDC relying party

Configure `AppState::with_oidc_rp(...)`. Login page links to `/login/oidc/start`.
Callback: `/login/oidc/callback`. ID tokens verified with `jose`.

## B2 — LDAP gateway

Configure `AppState::with_directory(Arc::new(MemoryDirectory::...))`.
`POST /login/ldap` with username/password. Real `ldap3` wire protocol is out of
scope for this slice.

## Out of scope

SAML, multi-IdP picker UI, account linking UI, back-channel logout, live LDAP in CI.

## Run

```bash
cargo test -p oauth federation::
cargo test -p oauth-http
```
