# M3 token lifecycle

**Status: in progress (B1+B2 landed).** Profile: [ADR 0008](adr/0008-token-lifecycle.md).

## B1 — rotating refresh tokens

| Piece | Location |
|---|---|
| Refresh store + rotation | `rust/crates/oauth` (`refresh`) |
| `grant_type=refresh_token` | `AuthorizationServer::exchange_token` |
| Protocol vectors | `testvectors/token/` |

Code exchange always returns an opaque `refresh_token`. Refreshing rotates it;
reuse of a consumed refresh revokes the family (`invalid_grant`). Refresh
responses do not include `id_token`. Access tokens carry `jti`.

## B2 — revoke + introspect

`POST /revoke` and `POST /introspect` on `oauth-http`. Access revoke denylists
`jti`; refresh revoke kills the family. UserInfo rejects denylisted tokens.

## Run

```bash
cargo test -p oauth --test vectors token_lifecycle
cargo test -p oauth-http
```
