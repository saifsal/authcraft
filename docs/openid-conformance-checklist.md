# OpenID conformance checklist (authcraft)

Educational mapping of OpenID Foundation **Basic OP** / related expectations to
this repository. Status values match [rfc-9700-checklist.md](rfc-9700-checklist.md):

- **done** — covered by shared vectors, attack harness, or library tests
- **partial** — implemented with documented gaps
- **open** — not run / not implemented (full OIDF suite remains external)

| Topic | Status | Notes |
|---|---|---|
| Authorization code + PKCE S256 | done | ADR 0005; `testvectors/oauth/` |
| `response_type=code` only (no implicit) | done | Attack / authorize path |
| ID Token (`iss`, `aud`, `exp`, `iat`, `nonce`, `at_hash`) | done | ADR 0006; `testvectors/oidc/` |
| Discovery (`/.well-known/openid-configuration`) | done | oauth-http |
| UserInfo endpoint | done | Bearer / DPoP-bound |
| Refresh token rotation | done | ADR 0008 |
| PAR (optional) | partial | ADR 0009; not required |
| DPoP (optional) | partial | ADR 0009 |
| Dynamic client registration | partial | `none` and `private_key_jwt` with inline `jwks` (ADR 0011 / 0014) |
| mTLS client auth + bound tokens (RFC 8705) | done | `self_signed_tls_client_auth` (ADR 0017) and PKI `tls_client_auth` with SAN matching (ADR 0019); `testvectors/mtls/` |
| Back-channel client auth (`private_key_jwt`) | done | `/token`, `/par`, `/revoke` (ADR 0014), `/introspect` (ADR 0016); `testvectors/client_auth/`, `testvectors/introspect/` |
| Request object / JAR | partial | `request` by value, `private_key_jwt` clients only, optional per-client `require_signed_request_object` (ADR 0015); no `request_uri` fetch, no JWE |
| Hybrid / implicit profiles | open | Not offered |
| Full OIDF conformance suite in CI | open | Operator-run; this checklist tracks gaps |
| Attack harness negatives | done | `oauth/tests/attack_harness.rs` (ADR 0013) |
| Parser fuzz smoke in CI | done | `rust/fuzz` + `fuzz-smoke` job |

Profile ADRs: 0005–0019. Runbook: [oauth-m8.md](oauth-m8.md).
