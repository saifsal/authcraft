# ADR 0006: M2 OpenID Connect (authorization code)

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

M1 delivered OAuth authorization code + PKCE and `at+jwt` access tokens
(ADR 0005). Relying parties that need identity need OpenID Connect on the same
flow: an ID token, discovery, and UserInfo. Authentication remains a stub (M5).

## Decision

### Scope trigger

1. When the authorize `scope` contains the space-delimited token `openid`, the
   request is an OIDC Authentication Request.
2. `nonce` is **required** when `openid` is present (OIDC Core §3.1.2.1) and is
   bound to the authorization code. Missing or empty `nonce` → `invalid_request`.
3. Without `openid`, behavior is unchanged from ADR 0005 (access token only;
   `nonce` is ignored if sent).

### ID token

- Compact JWS signed with **EdDSA**, header `typ` = `JWT`.
- Claims: `iss` (same issuer as access tokens), `sub`, `aud` = `client_id`,
  `exp`, `iat`, `nonce`, **`at_hash`**, optional `name` / `email` from stub login.
- Lifetime matches the access-token TTL (default 300s).
- `at_hash` follows OIDC Core §3.1.3.6 for EdDSA: SHA-256 over the ASCII
  access-token string, take the left-most 128 bits, unpadded base64url (same
  canonical rules as JOSE).

Token endpoint success with `openid`:

```json
{
  "access_token": "<at+jwt>",
  "token_type": "Bearer",
  "expires_in": 300,
  "id_token": "<JWT>"
}
```

### Stub profile claims

Stub login may supply optional `name` and `email`. They are stored on the code,
copied into the ID token and (when present) the access token, and returned from
UserInfo after access-token verification.

### Discovery

`GET /.well-known/openid-configuration` returns at least:

- `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`,
  `jwks_uri`
- `response_types_supported`: `["code"]`
- `grant_types_supported`: `["authorization_code"]`
- `subject_types_supported`: `["public"]`
- `id_token_signing_alg_values_supported`: `["EdDSA"]`
- `code_challenge_methods_supported`: `["S256"]`
- `scopes_supported` including `openid`

### UserInfo

`GET /userinfo` with `Authorization: Bearer <access_token>`.

- Verify the access token with the server JWKS and policy (`iss`, `aud` from
  config, `typ` = `at+jwt`).
- Response JSON: `sub` required; `name` / `email` when present on the token.
- Failures use HTTP 401 with OAuth Bearer error `invalid_token`.

### Still out of scope

Hybrid/implicit, refresh tokens, RP-initiated logout, `claims` / request
objects, confidential clients, cross-language OIDC vectors.

### Contract

Protocol cases live under `testvectors/oidc/` and are run by the `oauth` crate.
HTTP coverage remains Axum integration tests.

## Consequences

- M1 public-client PKCE flow stays the only grant; OIDC is an additive profile.
- Access tokens may carry optional profile claims so UserInfo stays stateless.
- EdDSA `at_hash` uses SHA-256 (OIDC hash for that signature algorithm family).

## Alternatives considered

- **Separate `oidc` crate.** Rejected for this slice; token exchange already
  lives in `oauth`.
- **Omit `at_hash`.** Rejected; A2 explicitly requires it for ID token binding.
- **Require `nonce` always.** Rejected; pure OAuth M1 clients must keep working.
