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
4. PAR is **optional** by default (`ServerConfig.require_par = false`);
   discovery mirrors that as `require_pushed_authorization_requests`.
   When `require_par` is true, `/authorize` without `request_uri` is
   `invalid_request`.
5. In-memory `ParStore` only.

## Amendments

### B2 — DPoP (RFC 9449)

1. Optional: without a `DPoP` header, `/token` issues Bearer access tokens (no
   `cnf`).
2. With `DPoP`: verify EdDSA proof (`typ`=`dpop+jwt`, embedded `jwk`, `htm`/`htu`,
   `iat` within 120s, unique `jti`); mint access token with
   `cnf: {"jkt":"<thumbprint>"}` and `token_type`=`DPoP`.
3. Embedded `jwk` is verified only for DPoP proofs (ADR 0003 still ignores
   header `jwk` for ordinary access-token verification).
4. If an access token has `cnf.jkt`, `/userinfo` requires a matching DPoP proof.
5. Discovery lists `dpop_signing_alg_values_supported: ["EdDSA"]`.

### B3 — Authorization response `iss` (RFC 9207)

1. Successful authorize redirects include `iss` equal to `ServerConfig.issuer`
   (mix-up mitigation from RFC 9700 / RFC 9207).
2. Discovery advertises `authorization_response_iss_parameter_supported: true`.

### B4 — Sender-constrained refresh (DPoP)

1. When `/token` issues a DPoP-bound access token (authorization-code grant),
   the refresh-token family stores that `jkt`.
2. Refreshing a bound family requires a DPoP proof whose thumbprint matches;
   mismatch or missing proof → `invalid_grant` (proof checked before rotate).
3. Unbound (Bearer) refresh families stay optional-DPoP as before.

### B5 — DPoP nonce from the AS

1. Every DPoP proof at `/token` and DPoP-bound `/userinfo` must include a
   `nonce` matching the AS current value; otherwise `use_dpop_nonce`.
2. HTTP responses carry `DPoP-Nonce` on success (next nonce) and on
   `use_dpop_nonce` (current challenge). Proof verification runs before
   authorization-code redeem / refresh rotate so a nonce challenge is retryable.
3. Nonce is checked before the proof `jti` is stored, so a challenge does not
   burn the client's jti.

## Consequences

- Front-channel authorization queries stay short when clients use PAR.
- Existing M1/M2/M3 demos keep working without PAR.
- Clients can detect authorization-server mix-up via `iss`.
- Stolen DPoP-bound refresh tokens are useless without the proof key.
- DPoP proofs are single-use against a fresh AS nonce (replay harder).

## Alternatives considered

- **Require PAR for all clients by default.** Demo keeps `require_par=false`;
  enforcement is available when the flag is set.
- **JAR / request objects.** Deferred; PAR body is enough for M4.
