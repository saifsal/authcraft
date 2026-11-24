# ADR 0015: JWT-secured authorization requests (JAR)

- **Status:** Accepted (amended as slices land)
- **Date:** 2026-11-24

## Context

Authorize parameters travel through the user agent, where they can be read or
changed. PAR (ADR 0009) moves them to the back channel. RFC 9101 (JAR) lets
the client sign them instead, so the AS can tell the parameters came from the
client unchanged. RFC 9700 lists JAR alongside PAR. ADR 0014 gave confidential
clients a registered JWKS, which is the key material a request object needs.

## Decision

1. `/authorize` and `/par` accept a `request` parameter holding a compact
   request object (by value). `request` together with `request_uri` is
   `invalid_request`. With `require_par`, a front-channel `request` without
   PAR is still `invalid_request`.
2. Only `private_key_jwt` clients (ADR 0014) can send request objects; they
   are verified against that client's registered JWKS. A public client sending
   `request` gets `invalid_request_object`.
3. Verification uses `jose::verify` (ADR 0003 order), `EdDSA` or `ES256`, and:
   - header `typ` = `oauth-authz-req+jwt` (RFC 9101 §10.8; required);
   - `iss` = outer `client_id`, and claim `client_id` = outer `client_id`;
   - `aud` is, or contains, the AS issuer identifier;
   - `exp` is required and at most **300 s** after `now`;
   - no nested `request` or `request_uri` claim;
   - each authorize claim that is present is a string.
   Any failure is `invalid_request_object` (HTTP 400).
4. Only the signed claims are used (RFC 9101 §5). Unsigned query or form
   parameters other than `client_id` are ignored. The expanded request then
   goes through the normal checks (registered `redirect_uri`, PKCE S256,
   `nonce` for `openid`), so those failures keep their usual codes.
5. At `/par`, client authentication (ADR 0014 B2) runs first, then the request
   object is expanded and stored like ordinary pushed parameters.
6. Discovery advertises `request_parameter_supported: true`,
   `request_uri_parameter_supported: false`, and
   `request_object_signing_alg_values_supported: ["EdDSA","ES256"]`.
7. Shared vectors: `testvectors/jar/`, signed with the RFC 8037 Appendix A.2
   key registered for client `svc`.

## Amendments

### B2 — Per-client `require_signed_request_object` (RFC 9101 §10.5)

1. `Client.require_signed_request_object` (default `false`). When true, plain
   authorize parameters are `invalid_request` at both `/authorize` and `/par`;
   only a `request` object (or a `request_uri` from PAR, which for such a
   client can only have come from a request object) is accepted.
2. Only `private_key_jwt` clients may set it. Registration (`POST /register`,
   `POST /admin/clients`) with the flag on a public client is
   `invalid_request`. Responses echo `require_signed_request_object`.
3. At `/par`, client authentication still runs first, so an unauthenticated
   push is `invalid_client` before the signed-request check.
4. Vectors: `svc-strict` cases in `testvectors/jar/`; registration cases in
   `testvectors/dcr/`.

## Not in this slice

- `request_uri` pointing at a client-hosted URL (only PAR URNs are accepted).
- Encrypted request objects (JWE).
- `jti` replay tracking for request objects. A replayed object only restarts
  a flow bound to the original PKCE challenge.

## Consequences

- RFC 9700 / OpenID checklist JAR rows move from open to partial; B2 lets an
  operator make JAR mandatory per client.
- `AuthorizeRequest` gains `request`; `OAuthError` gains
  `InvalidRequestObject`.
