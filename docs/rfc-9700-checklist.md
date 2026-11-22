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
| Pushed Authorization Requests | partial | Optional PAR (ADR 0009) |
| Mix-up mitigation (`iss` on AS responses) | open | Not yet on authorize redirects |
| Confidential clients / client auth | open | Public clients only |
| PAR required for public clients | open | `require_pushed_authorization_requests=false` |
| DPoP nonce from AS | open | Clock-skew `iat` only |
| Real resource-owner authentication | open | Stub login (M5) |
| TLS / production deployment | open | Local demo binds only |
| Sender-constrained refresh (DPoP) | open | Refresh tokens remain opaque bearer-style secrets |
| JAR / request objects | open | PAR body only |

Profile ADRs: [0005](adr/0005-oauth-code-pkce.md), [0008](adr/0008-token-lifecycle.md),
[0009](adr/0009-hardening-par-dpop.md). Runbook: [oauth-m4.md](oauth-m4.md).
