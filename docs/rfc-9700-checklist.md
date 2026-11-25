# RFC 9700 checklist (authcraft)

Educational mapping of [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
(OAuth 2.0 Security Best Current Practice) to this repository.

Status values:

- **done**: the recommendation is implemented in the Rust AS (`oauth` +
  `oauth-http`) and can be enforced. Where RFC 9700 says SHOULD and the
  mechanism is opt-in, the demo default is listed; turning it on needs no
  code change.
- **partial**: implemented, but a required part is missing.
- **open**: not implemented.

The RFC 9700 column cites the best-practice (§2) or attack (§4) section. A
dash marks a row kept for completeness that RFC 9700 does not number as its
own recommendation (PAR, JAR, and user authentication are profile choices
here).

Every row is done. "Demo default" is what `AppState::demo()` does; the
defaults stay lenient so the M1–M4 walkthroughs work with a plain public
client.

| Topic | RFC 9700 | Status | Demo default | Notes |
|---|---|---|---|---|
| Authorization code + PKCE (S256) | §2.1.1, §4.8 | done | on | ADR 0005; PKCE required for every client; `plain` rejected |
| Exact `redirect_uri` matching | §2.1, §4.1 | done | on | Exact match at `/authorize`; registration rejects fragments, non-loopback `http`, and unsafe schemes (ADR 0020) |
| No implicit / `token` response type | §2.1.2 | done | on | `response_type=code` only |
| No resource owner password credentials grant | §2.4 | done | on | Only `authorization_code` and `refresh_token`; `password` and `client_credentials` are `unsupported_grant_type` (ADR 0021 tests) |
| Mix-up mitigation (`iss` in authorization responses) | §2.1, §4.4 | done | on | RFC 9207 `iss` on authorize redirects (ADR 0009 B3) |
| CSRF protection | §2.1, §4.7 | done | on | PKCE is mandatory; `state` echoed when sent |
| Refresh token rotation + reuse detection | §2.2.2, §4.14 | done | on | ADR 0008 B1; reuse revokes the family |
| Refresh / access token revocation | §4.14 | done | on | ADR 0008 B2; client authentication at `/revoke` (ADR 0014 B2) |
| Sender-constrained access tokens (DPoP) | §2.2.1, §4.10.1 | done | opt-in | DPoP with AS nonces (ADR 0009); mandatory per client (`dpop_bound_access_tokens`) or server-wide (`require_sender_constrained_tokens`), ADR 0018 |
| Sender-constrained access tokens (mTLS) | §2.2.1, §4.10.1 | done | opt-in (HTTPS mode) | `cnf.x5t#S256` (ADR 0017); mandatory per client (`tls_client_certificate_bound_access_tokens`) or server-wide, ADR 0018 |
| Sender-constrained refresh tokens | §2.2.2 | done | when bound | Refresh families keep the DPoP `jkt` (ADR 0009 B4) or certificate thumbprint (ADR 0017) |
| Bound tokens enforced at resource servers | §2.2.1 | done | on | UserInfo checks DPoP / certificate; introspection returns `cnf` (ADR 0017 B2); Zig `authcraft-edge` refuses `cnf` tokens it cannot check (ADR 0007 B2) |
| DPoP nonce from AS | §2.2.1 | done | on | `use_dpop_nonce` + `DPoP-Nonce` (ADR 0009 B5) |
| Access token privilege restriction | §2.3, §4.10.2 | done | on | Access tokens carry the configured `aud` and the granted `scope`; one resource server audience (no RFC 8707 resource indicators) |
| Client authentication (asymmetric methods) | §2.5 | done | per client | `private_key_jwt` (ADR 0014, explicit `typ` per B3), `self_signed_tls_client_auth` (ADR 0017), PKI `tls_client_auth` with SAN matching (ADR 0019); at `/token`, `/par`, `/revoke`, `/introspect` (ADR 0016) |
| Pushed Authorization Requests | — | done | opt-in | PAR (ADR 0009); mandatory server-wide (`require_par`) or per client (`require_pushed_authorization_requests`, ADR 0018) |
| JWT-secured authorization requests (JAR) | — | done | opt-in | Signed `request` by value at `/authorize` and `/par`; per-client `require_signed_request_object` (ADR 0015). Client-hosted `request_uri` and encrypted request objects are not offered |
| Real resource-owner authentication | — | done | on | Argon2id + optional TOTP / WebAuthn (ADR 0010) |
| Clickjacking protection | §4.16 | done | on | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'` on every response (ADR 0021) |
| Referer leakage of codes and `state` | §4.2.4 | done | on | `Referrer-Policy: no-referrer` (ADR 0021) |
| No caching of token responses | RFC 6749 §5.1 | done | on | `Cache-Control: no-store`, `Pragma: no-cache` on token, PAR, registration, introspection, revocation, UserInfo (ADR 0021) |
| TLS | §2.6, §4.13 | done | off (loopback HTTP) | HTTPS listener with optional mTLS and HSTS when `AUTHCRAFT_TLS_CERT` / `AUTHCRAFT_TLS_KEY` are set (ADR 0017, ADR 0021). The demo binds only to `127.0.0.1` |

## Out of scope

These are not RFC 9700 requirements for this profile, and authcraft is not a
production identity provider:

- production deployment: certificate reload, non-loopback binds, key
  management, rate limiting, persistent storage;
- RFC 8707 resource indicators and multiple resource-server audiences;
- client-hosted JAR `request_uri`, JWE request objects, and `tls_client_auth`
  subject DN matching or intermediate chains (ADR 0015, ADR 0019).

Profile ADRs: [0005](adr/0005-oauth-code-pkce.md),
[0008](adr/0008-token-lifecycle.md), [0009](adr/0009-hardening-par-dpop.md),
[0010](adr/0010-authentication.md), [0014](adr/0014-private-key-jwt.md),
[0015](adr/0015-jar-request-objects.md),
[0016](adr/0016-protected-introspection.md),
[0017](adr/0017-mutual-tls.md), [0018](adr/0018-enforcement-metadata.md),
[0019](adr/0019-pki-tls-client-auth.md),
[0020](adr/0020-redirect-uri-registration.md),
[0021](adr/0021-http-security-headers.md). Runbook: [oauth-m4.md](oauth-m4.md).
