# ADR 0016: Protected token introspection

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

ADR 0008 B2 left `POST /introspect` unauthenticated: anyone holding a token
could learn its subject, scope, and client. RFC 7662 §2.1 requires the endpoint
to be protected, and §4 warns that an open endpoint lets an attacker probe
tokens. Its usual callers are resource servers, which this AS had no way to
register. ADR 0014 added `private_key_jwt`, which gives every confidential
caller a credential that holds no shared secret.

## Decision

1. `introspect` requires the caller's `client_id` plus a valid RFC 7523
   assertion, checked exactly as at `/token` (ADR 0014): same rules, same
   single-use `jti` cache.
2. Public (`none`) clients cannot authenticate and get `invalid_client`.
   Unknown callers get `unauthorized_client`. `oauth-http` answers both with
   HTTP 401 and an OAuth error body.
3. New `Client.resource_server` flag (default `false`):
   - a resource server may introspect tokens issued to any client;
   - any other authenticated client sees only tokens whose `client_id` is its
     own; every other token is reported as `{"active": false}` (§2.2), so the
     response does not reveal that the token exists.
4. The flag is set only through the admin API (`POST /admin/clients`,
   `resource_server: true`). RFC 7591 registration cannot grant it. A
   resource server must use `private_key_jwt` and may have no redirect URIs;
   all other clients still need at least one.
5. Each introspection call needs a fresh assertion. This is the cost of
   single-use assertions; a production AS would usually also offer mTLS or a
   longer-lived credential for resource servers.
6. Shared vectors: `testvectors/introspect/` (caller assertions signed with the
   RFC 8037 Appendix A.2 key). `testvectors/token/` revocation cases now
   introspect as a generated resource server.

## Consequences

- RFC 7662 is no longer "no client auth (demo)". The ADR 0008 B2 note is
  superseded by this ADR.
- `AuthorizationServer::introspect` takes `caller_client_id` and a
  `ClientAssertion`. The HTTP form adds `client_id`, `client_assertion_type`,
  and `client_assertion`.
- Discovery (RFC 8414) lists
  `introspection_endpoint_auth_methods_supported: ["private_key_jwt"]` and
  `revocation_endpoint_auth_methods_supported: ["none","private_key_jwt"]`.
