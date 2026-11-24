# RFC 9700 checklist (authcraft)

Educational mapping of [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
(OAuth 2.0 Security BCP) recommendations to this repository. Status values:

- **done** — enforced in the current Rust AS / JOSE stack
- **partial** — available or optional, not mandatory for all clients
- **open** — not implemented (later milestone or out of scope)

| Topic | Status | Notes |
|---|---|---|
| Authorization code + PKCE (S256) | done | ADR 0005; `plain` rejected |
| Exact `redirect_uri` matching | done | No open redirects |
| No implicit / `token` response type | done | `response_type=code` only |
| Refresh token rotation + reuse detection | done | ADR 0008 B1 |
| Refresh / access revocation | done | ADR 0008 B2 |
| Sender-constrained access tokens (DPoP) | partial | Optional DPoP (ADR 0009); Bearer still allowed |
| Sender-constrained access tokens (mTLS) | partial | `cnf.x5t#S256` when a client certificate is presented (ADR 0017); optional |
| Bound tokens at resource servers | done | `oauth-http` UserInfo checks DPoP / certificate; Zig `authcraft-edge` refuses `cnf` tokens it cannot check (ADR 0007 B2) |
| Pushed Authorization Requests | partial | Optional PAR; `require_par` available (ADR 0009) |
| Mix-up mitigation (`iss` on AS responses) | done | RFC 9207 `iss` on authorize success redirects |
| Confidential clients / client auth | partial | `private_key_jwt` at `/token`, `/par`, `/revoke` (ADR 0014) and `/introspect` (ADR 0016); explicit assertion `typ` (B3); `self_signed_tls_client_auth` (ADR 0017); no PKI `tls_client_auth` |
| PAR required for public clients | partial | `ServerConfig.require_par` (demo default false) |
| DPoP nonce from AS | done | `use_dpop_nonce` + `DPoP-Nonce` header (ADR 0009 B5) |
| Real resource-owner authentication | done | Argon2id + optional TOTP/WebAuthn 2FA (M5); stub login removed |
| TLS / production deployment | partial | Optional HTTPS + mTLS listener on loopback (ADR 0017); no production deployment |
| Sender-constrained refresh (DPoP) | done | Refresh family stores `jkt` when issued with DPoP |
| JAR / request objects | partial | Signed `request` by value at `/authorize` and `/par`; per-client `require_signed_request_object` (ADR 0015) |

Profile ADRs: [0005](adr/0005-oauth-code-pkce.md), [0008](adr/0008-token-lifecycle.md),
[0009](adr/0009-hardening-par-dpop.md), [0014](adr/0014-private-key-jwt.md), [0015](adr/0015-jar-request-objects.md), [0016](adr/0016-protected-introspection.md), [0017](adr/0017-mutual-tls.md). Runbook: [oauth-m4.md](oauth-m4.md).
