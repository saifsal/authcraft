# M7 federation

**Status: in progress** (B1 OIDC RP + B2 LDAP gateway landed; docs close next).
Profile: [ADR 0012](adr/0012-federation.md).

## B1 — OIDC relying party

Configure `AppState::with_oidc_rp(...)`. Login page links to `/login/oidc/start`.
Callback: `/login/oidc/callback`.

## B2 — LDAP gateway

Configure `AppState::with_directory(Arc::new(MemoryDirectory::...))`.
`POST /login/ldap` with username/password.

## Run

```bash
cargo test -p oauth federation::
cargo test -p oauth-http
```

