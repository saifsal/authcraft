# Threat model (authcraft)

This document lists what authcraft protects, from whom, and how. Each
mitigation points at the ADR and the tests or vectors that check it. It covers
the tree as of ADR 0022.

authcraft is an educational, unreviewed OAuth 2.0 / OpenID Connect
authorization server. This model describes the design so its gaps are
explicit. It does not claim production readiness.

## Scope and assumptions

In scope:

- `rust/crates/oauth`: the authorization server library;
- `rust/crates/oauth-http`: the Axum binder, the demo binary, and the
  optional HTTPS / mTLS listener;
- `rust/crates/jose`, `zig/`, and `go/jose`: JOSE verification;
- `zig` `authcraft-edge`: the verify-only sidecar.

Assumptions:

- **A1.** One process. In production, accounts (SQLite) and the signing key
  (a 0600 file) persist in the data directory (ADR 0023, 0024); codes,
  refresh families, caches, and the revocation denylist are in memory and a
  restart forgets them. `--demo` keeps everything in memory.
- **A2.** The server binds to `127.0.0.1`. In production (M9) it sits
  behind Caddy on the accumu.cc VPS, which terminates TLS and replaces
  `X-Forwarded-For` (ADR 0027).
- **A3.** The host and the process are trusted. An attacker with code
  execution or memory access on the host is out of scope.
- **A4.** `ring`, `rustls`, `rustls-webpki`, `x509-parser`, `argon2`, and
  `webauthn-rs` are correct. The JOSE layer, PKCE, the token logic, and the
  protocol checks around them are written here and are in scope.

## Assets

| Asset | Where | Impact if lost |
|---|---|---|
| AS signing keys (Ed25519 PKCS#8) | `Keyring` in memory | Forge any access or ID token |
| Access tokens (`at+jwt`, 300 s) | Clients, resource servers | Act as the user until expiry, unless bound |
| Refresh tokens (opaque, 24 h, rotating) | Clients | New access tokens until the family is revoked |
| Authorization codes (60 s, one use) | Front channel | Token exchange, but PKCE is still required |
| User passwords | Argon2id PHC hashes in `UserStore` | Account takeover |
| TOTP secrets, WebAuthn credentials | `UserStore` | Bypass of the second factor |
| Admin bearer token | `ServerConfig.admin_token` | Full control of clients and users |
| Client credentials | Client side: private keys and TLS keys; AS keeps only public JWKS and certificate thumbprints | Impersonate a confidential client |
| Login and MFA tickets | `authcraft_login` cookie, maps in `AppState` | Resume someone else's login |

## Adversaries

- **Network attacker:** observes or changes traffic between parties.
  Relevant when plain HTTP is used off-loopback.
- **Malicious client:** registers through open RFC 7591 registration and
  tries to obtain tokens or codes meant for others.
- **Malicious web page:** in the user's browser; attempts CSRF,
  clickjacking, and mix-up.
- **Token thief:** has copied an access or refresh token, for example from
  logs, a compromised resource server, or browser storage.
- **Credential attacker:** knows or guesses a user's password and attacks the
  second factor.
- **Compromised resource server:** receives tokens and tries to replay them
  elsewhere.

## Trust boundaries

```
 browser ──(1) front channel: /authorize, /login, /login/mfa──┐
                                                             ▼
 client ───(2) back channel: /token /par /revoke /introspect─► oauth-http ─► oauth (AS)
                                                             ▲     │
 admin ────(3) /admin, /scim (bearer token)──────────────────┘     │ JWKS
                                                                   ▼
 resource server / authcraft-edge ◄──(4) bearer or bound access token
```

1. **Front channel.** Everything passes through the browser, so it can be
   seen and changed.
2. **Back channel.** The client authenticates (or is public); TLS is
   optional.
3. **Admin.** A single shared bearer token.
4. **Resource side.** Tokens are verified offline with the AS JWKS, or
   through introspection.

## Threats and mitigations

Status: **mitigated** (a mitigation with tests), **accepted** (a documented
residual risk), or **open** (worth fixing).

### Authorization endpoint and front channel

| Threat | Mitigation | Status |
|---|---|---|
| Code interception or injection | PKCE S256 required for every client; `plain` refused (ADR 0005; `testvectors/oauth/`) | mitigated |
| Code replay | Codes are single-use with a 60 s TTL (`neg-replay-code`) | mitigated |
| Open redirect / redirect URI manipulation | Exact match at `/authorize`; registration refuses fragments, non-loopback `http`, and unsafe schemes (ADR 0020; `testvectors/dcr/`) | mitigated |
| Implicit-flow token leakage | Only `response_type=code` | mitigated |
| Mix-up across authorization servers | RFC 9207 `iss` on authorize redirects (ADR 0009 B3) | mitigated |
| CSRF on the authorization response | PKCE binds the code to the client's verifier; `state` echoed | mitigated |
| Login CSRF / ticket fixation | Ticket is a 128-bit random value set at `/authorize`; `HttpOnly`, `SameSite=Lax`, and `Secure` under HTTPS (ADR 0021 B2); expires after 10 min (ADR 0026) | mitigated |
| SSO session theft or fixation | 256-bit random cookie, stored hashed, issued only after sign-in, `HttpOnly` / `SameSite=Lax` / `Secure`, 24 h; reset ends sessions (ADR 0026) | mitigated |
| Forced logout (CSRF) | `POST /logout` requires the session's CSRF token (ADR 0026) | mitigated |
| Open redirect after sign-in | `return_to` must be a local path (ADR 0026; `tests/sso.rs`) | mitigated |
| Clickjacking of login or consent pages | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'` (ADR 0021) | mitigated |
| Code or `state` leaking through `Referer` | `Referrer-Policy: no-referrer` (ADR 0021) | mitigated |
| Tampering with authorize parameters in the browser | Optional PAR and JAR, mandatory per client (ADR 0009, 0015, 0018) | mitigated (opt-in) |
| JAR request object replayed as a client assertion | Client assertions refuse foreign `typ`, such as `oauth-authz-req+jwt` (ADR 0014 B3; `neg-typ-request-object`) | mitigated |
| Malicious client registered by anyone (phishing consent, resource exhaustion) | Registration is open and unauthenticated; redirect URI rules limit the schemes | accepted (see R2) |

### Token endpoint and client authentication

| Threat | Mitigation | Status |
|---|---|---|
| Confidential client impersonation | `private_key_jwt`, `self_signed_tls_client_auth`, PKI `tls_client_auth` (ADR 0014, 0017, 0019; `testvectors/client_auth/`, `mtls/`) | mitigated |
| Client assertion replay | Single-use `jti` per client until `exp`, at most 300 s, shared across endpoints (`neg-replay-assertion`, `neg-par-assertion-replayed-at-token`) | mitigated |
| Audience injection with client assertions | `aud` must be the issuer, not an endpoint URL (rfc7523bis; `neg-aud-token-endpoint`) | mitigated |
| Failed request consuming a code or refresh token | Client authentication, sender-constraint checks, and DPoP run before redemption or rotation (ADR 0014, 0018; enforcement vectors retry) | mitigated |
| Password grant credential exposure | No `password` or `client_credentials` grant (ADR 0021 tests) | mitigated |
| Token responses cached by intermediaries | `Cache-Control: no-store`, `Pragma: no-cache` (ADR 0021) | mitigated |

### Token theft and replay

| Threat | Mitigation | Status |
|---|---|---|
| Stolen access token reused | DPoP (`cnf.jkt`) or mTLS (`cnf.x5t#S256`) binding, mandatory per client or server-wide (ADR 0009, 0017, 0018) | mitigated (opt-in) |
| Stolen refresh token reused | Rotation with reuse detection that revokes the family; DPoP or certificate binding of the family (ADR 0008, 0009 B4, 0017) | mitigated |
| DPoP proof replay | `jti` cache, `iat` window, AS-issued nonces (ADR 0009 B2/B5) | mitigated |
| Bound token used where binding is not checked | UserInfo checks binding; introspection returns `cnf`; `authcraft-edge` refuses `cnf` tokens (ADR 0007 B2, 0017 B2) | mitigated |
| Bearer token from an unconstrained client | Bearer tokens remain the demo default for public clients | accepted (see R1) |
| Revoked access token still accepted | `jti` denylist checked by the AS (UserInfo, introspection); offline verifiers such as `authcraft-edge` do not see it before `exp` | accepted (300 s exposure) |
| Introspection used to probe tokens | Callers authenticate; non-resource-server callers see only their own tokens (ADR 0016) | mitigated |

### JOSE verification

| Threat | Mitigation | Status |
|---|---|---|
| `alg: none`, algorithm confusion (HS256 with a public key) | Allowlist per policy; no `none`; key `alg` must match; HS256 keys must be at least 32 bytes (ADR 0001, 0003; `neg-alg-none`, `neg-hs256-confusion`) | mitigated |
| Attacker-supplied keys (`jku`, `jwk`, `x5u`, `x5c`) | Ignored; keys come only from the caller's JWKS (`neg-jku-ignored`) | mitigated |
| Parser differentials (duplicate keys, non-canonical base64url, `crit`) | Strict parsers in Rust, Zig, and Go, cross-checked on shared vectors and differentially against `jose-cli` (ADR 0002, 0003) | mitigated |
| Malformed input crashing the verifier | cargo-fuzz targets in a CI smoke run (ADR 0013) | mitigated |
| Cross-JWT confusion (access token, ID token, DPoP proof, assertion, request object) | Access tokens require `typ` `at+jwt`, DPoP proofs `dpop+jwt`, request objects `oauth-authz-req+jwt`; client assertions refuse other explicit types. ID tokens use `typ` `JWT` (OIDC Core); key separation keeps AS-signed tokens from passing as client-signed ones, and the reverse | mitigated |

### Resource-owner authentication

| Threat | Mitigation | Status |
|---|---|---|
| Offline password cracking from the user store | Argon2id with crate defaults (19 MiB, t=2, p=1) (ADR 0010) | mitigated |
| User enumeration through login timing | Unknown users are checked against a dummy hash | mitigated |
| Online TOTP brute force | Per-user lockout after 5 failures for 300 s (ADR 0022; `neg-totp-locked`) | mitigated |
| TOTP code replay | A time step already accepted is refused (ADR 0022; `neg-totp-replay`) | mitigated |
| WebAuthn phishing | Origin- and RP-ID-bound assertions through `webauthn-rs` (ADR 0010) | mitigated |
| Online password guessing | 10 failures per account and 50 attempts per client address per 15 min (ADR 0025; `tests/accounts.rs`) | mitigated |
| Account enumeration through sign-up or recovery | Identical responses for every address; notices by email (ADR 0025) | mitigated |
| Pre-registration of someone else's address | Password and name apply only when the verify link is used (ADR 0025) | mitigated |
| Email link theft or replay | 256-bit single-use tokens stored hashed; 24 h / 30 min; GET does not consume (ADR 0025) | mitigated |
| Federated login (OIDC RP) code or ID token injection | Upstream flow uses PKCE S256, `state`, `nonce`; ID token checked for `iss` and `aud` (ADR 0012) | mitigated |

### Administration and control plane

| Threat | Mitigation | Status |
|---|---|---|
| Admin token guessing or timing leak | Constant-time digest comparison (ADR 0021 B2); an empty token disables admin | mitigated |
| Admin token is a published demo constant | `DEMO_ADMIN_TOKEN` is set by `AppState::demo()` | accepted (demo only, see R4) |
| Privilege escalation through registration | DCR cannot grant `resource_server`; inconsistent auth or binding metadata refused (ADR 0016, 0018) | mitigated |

### Availability

| Threat | Mitigation | Status |
|---|---|---|
| Login flood exhausting CPU (Argon2id per attempt) | None | accepted (see R3) |
| Unbounded in-memory growth | Codes, PAR URIs, DPoP and assertion `jti` caches, login and MFA tickets (ADR 0026), and sessions expire; production has no open registration (ADR 0023) | mitigated |

### Transport

| Threat | Mitigation | Status |
|---|---|---|
| Eavesdropping or tampering on the network | HTTPS listener with HSTS (ADR 0017, 0021); demo default is HTTP on loopback only (A2) | mitigated (opt-in) |
| Client certificate presented without its private key | rustls verifies the handshake signature (ADR 0017) | mitigated |
| `authcraft-edge` exposed off-host | Binds `127.0.0.1:8091` by default, but `--listen` accepts any address and there is no TLS | accepted (see R6) |

## Residual risks

Ordered by how much each one matters if the code were reused.

- **R1. Bearer tokens by default.** Sender-constraint is opt-in so the
  walkthroughs work. Anyone reusing this code should turn on
  `require_sender_constrained_tokens` or the per-client flags (ADR 0018).
- **R2. Open dynamic registration.** Closed in production (ADR 0023:
  clients come from a configuration file). Under `--demo`, anyone can
  register clients. Combined
  with no client expiry, this enables consent phishing under a chosen
  `client_name` and memory growth. Production servers usually require an
  initial access token (RFC 7591 §3).
- **R3. Rate limiting is partial.** Logins (per account and client address),
  sign-up, recovery, and mail are limited (ADR 0025), and TOTP is locked out
  (ADR 0022). The OAuth endpoints themselves (`/token`, `/par`, `/authorize`)
  are not rate-limited, and an attacker who knows an address can lock its
  password login for up to 15 minutes.
- **R4. Demo secrets.** `DEMO_ADMIN_TOKEN` and the demo password for `alice`
  are published constants. Since ADR 0023 they exist only under `--demo`;
  production refuses the demo admin token and seeds no users.
- **R5. Pending tickets never expire.** Closed: tickets expire after 10
  minutes and are swept (ADR 0026).
- **R6. Sidecar transport.** `authcraft-edge` has no TLS. It is meant to sit
  next to a proxy on the same host.
- **R7. Revocation visibility.** Offline verifiers accept a revoked access
  token until it expires (at most 300 s).
- **R8. No audit log.** Security events (failed logins, lockouts, refresh
  reuse, admin actions) are not recorded.

## Fixed while writing this model

Writing this model found three weaknesses, now fixed:

- unlimited TOTP guesses and code replay (ADR 0022);
- the login cookie lacking `Secure` under HTTPS (ADR 0021 B2);
- the admin token compared with `==` rather than in constant time
  (ADR 0021 B2).

## Keeping this current

Update this file when a change adds an endpoint, a credential type, a
token type, or a trust boundary, or when it closes a residual risk. Each
mitigation row should name the ADR and the test or vector that checks it.
