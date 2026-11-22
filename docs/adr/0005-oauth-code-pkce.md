# ADR 0005: M1 authorization code + PKCE profile

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

M0 delivered independent JOSE verifiers and shared vectors. M1 adds the OAuth 2.0
authorization-code flow so the project can issue access tokens that those
verifiers accept. The first slice must stay small enough to test as a library,
while still exposing a thin HTTP surface for demos.

RFC 9700 and common practice require PKCE for public clients. Real user
authentication (passwords, WebAuthn) belongs to M5 ([ADR 0010](0010-authentication.md));
this milestone originally used a stub subject so the code path was exercisable.
The stub has been replaced by Argon2id passwords (M5 B1).

## Decision

### Clients

1. **Public clients only.** No client secret. Confidential clients are later.
2. Each client has a stable `client_id` and an allowlist of `redirect_uri` values
   compared by exact string equality (no open redirects, no path normalization).

### Authorization endpoint (`GET /authorize`)

Required query parameters:

| Parameter | Rule |
|---|---|
| `response_type` | Must be `code` |
| `client_id` | Must name a registered client |
| `redirect_uri` | Must be in that client's allowlist |
| `code_challenge` | Required |
| `code_challenge_method` | Must be `S256` (`plain` is rejected) |

Optional: `state` (returned on redirect), `scope` (opaque space-separated string;
stored and echoed into the token as a string claim when present).

On success the server authenticates the resource owner via the stub login, then
redirects to `redirect_uri` with `code` and `state` (if supplied). On failure
before a safe redirect target is known, the HTTP layer returns a non-redirect
error; once `redirect_uri` is validated, errors are returned as query parameters
on that URI (`error`, optional `error_description`, `state`).

### Stub login

`GET/POST /login` selects a subject string (default `alice`) for the pending
authorization. No passwords. This exists only so `/authorize` can complete.

### Token endpoint (`POST /token`)

`application/x-www-form-urlencoded` body:

| Parameter | Rule |
|---|---|
| `grant_type` | Must be `authorization_code` |
| `code` | One-time authorization code |
| `redirect_uri` | Must equal the URI bound to the code |
| `client_id` | Must equal the client bound to the code |
| `code_verifier` | Must satisfy S256 against the stored challenge |

Public clients send no `client_secret`. A successful response is JSON:

```json
{
  "access_token": "<compact JWT>",
  "token_type": "Bearer",
  "expires_in": 300
}
```

No refresh token in M1.

### Access token profile

- Compact JWS signed with **EdDSA** (ADR 0001) using the server signing key.
- Header: `alg`, `kid` (RFC 7638 thumbprint), `typ` = `at+jwt`.
- Claims: `iss`, `aud` (configured), `sub` (stub subject), `exp`, `iat`,
  optional `scope` string, `client_id`.
- Lifetime defaults to **300 seconds**. `exp` is required (ADR 0003).

### PKCE (RFC 7636)

- `code_verifier`: 43–128 characters from `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
- `code_challenge` for `S256` is `BASE64URL(SHA256(verifier))` using the same
  unpadded canonical base64url as JOSE.
- `plain` is never accepted.

### Authorization codes

- Cryptographically random, opaque, single use.
- Bound to `client_id`, `redirect_uri`, `code_challenge`, subject, optional scope.
- Expire after a short TTL (default 60 seconds). Replay after redeem or expiry
  yields `invalid_grant`.

### Error codes (wire)

Stable OAuth error strings returned by the library and HTTP layer:

| Code | Typical cause |
|---|---|
| `invalid_request` | Missing/malformed parameters, `plain` PKCE, bad `response_type` |
| `unauthorized_client` | Unknown `client_id` |
| `access_denied` | Stub login cancelled (reserved; unused if stub always accepts) |
| `invalid_grant` | Bad/expired/replayed code, verifier mismatch, redirect_uri mismatch |
| `unsupported_grant_type` | `grant_type` other than `authorization_code` |
| `server_error` | Signing or internal failure |

### Discovery helpers (HTTP only)

- `GET /healthz` — liveness.
- `GET /.well-known/jwks.json` — public JWKS for the signing key.

### Contract

Protocol cases live under `testvectors/oauth/` and are run by the `oauth` crate.
The HTTP wrapper is covered by Axum integration tests, not cross-language vectors.

## Consequences

- Relying parties that need confidential clients, refresh tokens, or OIDC must
  wait for later milestones.
- Stub login is not authentication; demos must not be exposed without TLS and a
  real authn story (M5).
- Exact `redirect_uri` matching rejects common “prefix” open-redirect bugs by
  construction.

## Alternatives considered

- **Allow `plain` PKCE.** Rejected; RFC 9700 and this profile require S256.
- **Library only, no HTTP.** Rejected for this slice; demos and e2e need a binder.
- **SQLite for codes.** Deferred; in-memory stores keep M1 focused on the protocol.
