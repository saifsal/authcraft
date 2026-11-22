# ADR 0008: M3 token lifecycle

- **Status:** Accepted (amended as M3 slices land)
- **Date:** 2026-11-22

## Context

M1/M2 issue short-lived `at+jwt` access tokens and (for OIDC) ID tokens, but
have no refresh path, revocation, or signing-key rotation. M3 adds those
lifecycle pieces on the same Rust crates without confidential-client auth.

## Decision — B1: rotating refresh tokens

1. **Opaque refresh tokens** (cryptographically random base64url), not JWTs.
2. Issued on every successful authorization-code exchange (demo profile).
3. Bound to `client_id`, `subject`, `scope`, optional `name`/`email`, and a
   **family id**. TTL default **86400** seconds.
4. **Rotation:** `grant_type=refresh_token` with `refresh_token` + `client_id`
   consumes the presented token and issues a new access token and a new refresh
   token in the same family. Refresh responses do **not** include `id_token`.
5. **Reuse detection:** presenting a previously consumed refresh token revokes
   the entire family and returns `invalid_grant`.
6. Access tokens include a `jti` claim (opaque) for later revocation (B2).

### Token success (code or refresh)

```json
{
  "access_token": "<at+jwt>",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_token": "<opaque>",
  "id_token": "<optional, code+openid only>"
}
```

## Amendments

### B2 — revocation and introspection

1. **`POST /revoke` (RFC 7009):** form `token`, optional `token_type_hint`
   (`access_token` | `refresh_token`), and `client_id` for public clients.
   Always returns success to the HTTP layer for unknown tokens. Revoking a
   refresh token revokes its **family**. Revoking an access token verifies it,
   then denylists `jti` until `exp`.
2. **`POST /introspect` (RFC 7662):** form `token` (+ optional hint / `client_id`).
   Response includes `active` and, when active, `client_id`, `sub`, `scope`,
   `exp`, `iat`, `token_type`. No client authentication in this educational
   demo (document as non-production).
3. **UserInfo** (and other access-token acceptors) reject denylisted `jti` with
   `invalid_token` after JOSE verification.

### B3 — signing key rotation

1. **`Keyring`** holds EdDSA keys; index 0 is the current signer.
2. **`rotate_signing_key(now)`** generates a new current key; the previous key
   remains in JWKS until `now + verify_grace_secs` (default **3600**).
3. JWKS lists all keys still within grace; minting always uses the current key
   (`kid` = thumbprint). No public HTTP rotate endpoint in the demo — library
   API + tests only.

## Consequences

- Public clients can renew access without re-auth until refresh expiry or reuse.
- Family revocation on reuse limits stolen-refresh windows.
- Still educational: in-memory stores, no client authentication on token APIs.

## Alternatives considered

- **JWT refresh tokens.** Rejected; opacity + server-side family state is simpler
  for rotation and reuse detection.
- **Refresh returns ID tokens.** Rejected for B1; no fresh `nonce` on refresh.
