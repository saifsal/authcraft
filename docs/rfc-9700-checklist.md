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
| Pushed Authorization Requests | partial | Optional PAR; `require_par` available (ADR 0009) |
| Mix-up mitigation (`iss` on AS responses) | done | RFC 9207 `iss` on authorize success redirects |
| Confidential clients / client auth | open | Public clients only |
| PAR required for public clients | partial | `ServerConfig.require_par` (demo default false) |
| DPoP nonce from AS | done | `use_dpop_nonce` + `DPoP-Nonce` header (ADR 0009 B5) |
| Real resource-owner authentication | done | Argon2id + optional TOTP/WebAuthn 2FA (M5); stub login removed |
| TLS / production deployment | open | Local demo binds only |
| Sender-constrained refresh (DPoP) | done | Refresh family stores `jkt` when issued with DPoP |
| JAR / request objects | open | PAR body only |

Profile ADRs: [0005](adr/0005-oauth-code-pkce.md), [0008](adr/0008-token-lifecycle.md),
[0009](adr/0009-hardening-par-dpop.md). Runbook: [oauth-m4.md](oauth-m4.md).
