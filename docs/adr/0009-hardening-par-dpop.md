# ADR 0009: M4 hardening (PAR + DPoP)

- **Status:** Accepted (amended as M4 slices land)
- **Date:** 2026-11-22

## Context

M1–M3 deliver authorization code + PKCE, OIDC, and token lifecycle. RFC 9700
and modern clients expect pushed authorization requests and sender-constrained
access tokens. M4 adds those without confidential-client auth or real login.

## Decision — B1: PAR (RFC 9126)

1. `POST /par` accepts the same form fields as `/authorize` (`response_type`,
   `client_id`, `redirect_uri`, PKCE S256, optional `state`/`scope`/`nonce`).
2. Success: `request_uri` =
   `urn:ietf:params:oauth:request_uri:<opaque>` and `expires_in` (default **60**).
3. `GET /authorize` may use `client_id` + `request_uri` instead of the full
   query. The URI is **single-use**. Wrong `client_id`, unknown, expired, or
   replayed URI → `invalid_request`.
4. PAR is **optional**; direct `/authorize` remains valid.
   `require_pushed_authorization_requests` is `false` in discovery.
5. In-memory `ParStore` only.

## Amendments

### B2 — DPoP (RFC 9449)

*(filled in DPoP commit)*

## Consequences

- Front-channel authorization queries stay short when clients use PAR.
- Existing M1/M2/M3 demos keep working without PAR.

## Alternatives considered

- **Require PAR for all clients.** Rejected for this educational slice.
- **JAR / request objects.** Deferred; PAR body is enough for M4.
