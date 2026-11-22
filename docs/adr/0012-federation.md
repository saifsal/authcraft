# ADR 0012: M7 federation (OIDC RP, LDAP)

- **Status:** Accepted (amended as M7 slices land)
- **Date:** 2026-11-22

## Context

M1–M6 authenticate resource owners locally (passwords / MFA). Many deployments
need to trust an upstream OpenID Provider or an LDAP directory. M7 adds those
as alternate paths to the same `LoginSubject` → `finish_authorize` bridge.

## Decision — B1: OIDC relying-party connector

1. Optional `OidcRpConfig` on the HTTP `AppState` (`issuer`, `client_id`,
   optional `client_secret`, `redirect_uri`, `scopes`).
2. `GET /login/oidc/start` loads upstream discovery, starts PKCE S256 authorize
   (state + nonce), stores pending RP state keyed by `state`.
3. `GET /login/oidc/callback` exchanges the code, fetches JWKS, verifies the
   ID token with `jose` (issuer, aud=`client_id`, nonce), maps `sub` / `name` /
   `email` to `LoginSubject`, then `finish_authorize`.
4. JIT: no local `UserStore` row required. Local MFA does not apply to this path.
5. Library helpers live in `oauth::federation::oidc_rp`.

## Amendments

### B2 — LDAP (pending)

## Consequences

- Demo leaves `oidc_rp` unset unless tests configure it.
- Requires outbound HTTP (`reqwest`) from `oauth-http`.

## Alternatives considered

- **Loopback to self as upstream.** Rejected for tests; use an ephemeral stub OP.
- **SAML.** Deferred.
