# ADR 0014: Confidential clients with `private_key_jwt`

- **Status:** Accepted (amended as slices land)
- **Date:** 2026-11-24

## Context

Through M8 every client is public (`token_endpoint_auth_method` = `none`) and
relies on PKCE alone. RFC 9700 §2.5 recommends client authentication for
clients that can hold credentials and prefers asymmetric methods
(`private_key_jwt`, mTLS) over shared secrets. The `jose` crate already
verifies EdDSA and ES256 compact JWTs against a caller-supplied JWKS, so
`private_key_jwt` (RFC 7523 §2.2, OIDC Core §9) can reuse it without storing
any client secret.

## Decision

1. `Client` carries `token_endpoint_auth`: `None` (public, default) or
   `PrivateKeyJwt { jwks }`, the client's registered public JWKS document.
   `client_secret_*` methods and `jwks_uri` are not supported.
2. At `/token` (both `authorization_code` and `refresh_token` grants) the AS
   authenticates the client **before** any DPoP proof, authorization code, or
   refresh token is consumed:
   - A `private_key_jwt` client must send
     `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
     and a `client_assertion`.
   - A public client that sends either parameter is rejected.
   - `client_id` stays required in the form and must name the client.
3. The assertion is verified with `jose::verify` (ADR 0003 order) against the
   client's JWKS, allowing `EdDSA` and `ES256` (no `HS256`). Then:
   - `iss` = `sub` = `client_id`;
   - `aud` is, or contains, the AS **issuer identifier**. The token endpoint
     URL is not accepted (draft-ietf-oauth-rfc7523bis audience-injection fix);
   - `exp` is required and at most **300 s** after `now`;
   - `jti` is required and single-use per client until `exp`.
   `kid` is required, as for every token this verifier accepts.
4. Every client-authentication failure is `invalid_client` (RFC 6749 §5.2);
   `oauth-http` returns HTTP 401. Because assertions are single-use, a client
   retrying after `use_dpop_nonce` must mint a new assertion.
5. PKCE S256 stays mandatory for confidential clients.
6. Registration: RFC 7591 `POST /register` and `POST /admin/clients` accept
   `token_endpoint_auth_method: "private_key_jwt"` with an inline `jwks`
   object holding at least one parseable key. `jwks` without
   `private_key_jwt`, or `private_key_jwt` without `jwks`, is
   `invalid_request`.
7. Discovery advertises
   `token_endpoint_auth_methods_supported: ["none","private_key_jwt"]` and
   `token_endpoint_auth_signing_alg_values_supported: ["EdDSA","ES256"]`.
8. Shared vectors: `testvectors/client_auth/` (assertions signed with the
   published RFC 8037 Appendix A.2 Ed25519 key) and `private_key_jwt` cases in
   `testvectors/dcr/`.

## Amendments

### B2 — Client authentication at `/par` and `/revoke`

1. `POST /par` (RFC 9126 §2) and `POST /revoke` (RFC 7009 §2.1) apply the same
   client authentication as `/token`: `private_key_jwt` clients must send a
   valid assertion, public clients must not send one. The library takes a
   `ClientAssertion { client_assertion_type, client_assertion }` argument on
   `push_authorization` and `revoke`.
2. Authentication runs first: at `/par` before parameters are validated or a
   `request_uri` is issued; at `/revoke` before any token lookup.
3. The `jti` cache is shared across endpoints, so an assertion accepted at
   `/par` cannot be replayed at `/token` or `/revoke`.
4. `aud` is still the issuer identifier only. RFC 9126 also allows the token
   or PAR endpoint URL; this profile does not (rfc7523bis).
5. `oauth-http` returns HTTP 401 with `invalid_client` (or
   `unauthorized_client` for an unknown `client_id`) from both endpoints.
   `/revoke` previously answered 200 for an unknown client; once the client is
   authenticated it still answers 200 whether or not the token was valid.
6. Vectors: `endpoint: "par"` / `"revoke"` cases in `testvectors/client_auth/`.

## Not in this slice

- Protecting `/introspect` (RFC 7662 §2.1); done in
  [ADR 0016](0016-protected-introspection.md).
- `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, mTLS
  (RFC 8705), and `jwks_uri` fetching.
- A `typ` requirement on the assertion
  (`client-authentication+jwt` from rfc7523bis).

## Consequences

- RFC 9700 "confidential clients / client auth" moves from open to partial
  (B1) and covers `/token`, `/par`, and `/revoke` after B2.
- `TokenRequest` gains `client_assertion_type` and `client_assertion`;
  `DynamicClientRequest` gains `jwks`; `OAuthError` gains `InvalidClient`.
