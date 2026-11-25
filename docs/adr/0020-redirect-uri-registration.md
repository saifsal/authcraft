# ADR 0020: Redirect URI registration rules

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Authorization requests already require an exact match against a registered
redirect URI (ADR 0005). What could be registered was unchecked: RFC 7591
registration and `POST /admin/clients` accepted any non-empty string,
including `http://` URIs for public hosts, fragments, and `javascript:`.
RFC 9700 §2.1 and §4.1 call for exact matching of registered values; RFC 6749
§3.1.2 forbids fragments; RFC 8252 limits plain `http` to loopback for native
apps.

## Decision

`oauth::client::redirect_uri_allowed` is applied to every URI at registration
and admin creation. A URI must:

1. parse as an absolute URI with no fragment and no user information;
2. use `https` with a host, or `http` only with a loopback host
   (`localhost`, `127.0.0.1`, `[::1]`); or
3. use a private-use scheme that contains a `.` (RFC 8252 §7.1 reverse domain
   name). This excludes `javascript:`, `data:`, and `file:`.

One invalid URI rejects the whole registration with `invalid_request`.
Clients passed to `AuthorizationServer::new` are configuration and are not
re-checked. Vectors: `testvectors/dcr/`.

## Consequences

- Matching at `/authorize` is unchanged (exact string equality).
- Loopback redirect URIs still need an exact port match; RFC 8252 §7.3
  variable loopback ports are not supported.
