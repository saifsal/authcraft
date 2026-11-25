# ADR 0021: HTTP security headers

- **Status:** Accepted (amended as slices land)
- **Date:** 2026-11-25

## Context

Reviewing `oauth-http` against RFC 9700 found three response-level gaps:

- §4.16 (clickjacking): login and consent pages should not be frameable by
  other origins. No framing headers were sent.
- §4.2.4: authorization codes and `state` can leak through the `Referer`
  header. No `Referrer-Policy` was sent.
- RFC 6749 §5.1: token responses must carry `Cache-Control: no-store` and
  `Pragma: no-cache`. Neither was sent.

The optional HTTPS listener (ADR 0017) also sent no HSTS header.

## Decision

1. Middleware in `oauth_http::app` adds to every response
   `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`,
   and `Referrer-Policy: no-referrer`.
2. Responses from `/token`, `/par`, `/register`, `/introspect`, `/revoke`, and
   `/userinfo` also get `Cache-Control: no-store` and `Pragma: no-cache`.
3. `tls::serve_tls` adds `Strict-Transport-Security: max-age=31536000` to
   every HTTPS response. Plain HTTP never sends it (RFC 6797 §7.2).
4. Tests: `oauth-http/tests/confidential.rs` (framing, referrer, cache
   headers; unsupported `password` / `client_credentials` grants) and
   `tests/mtls.rs` (HSTS over real TLS).

## Amendments

### B2 — Login cookie and admin token

1. `serve_tls` marks requests with an `Https` extension. The
   `authcraft_login` cookie then carries `Secure` in addition to `HttpOnly`
   and `SameSite=Lax`, so the browser never sends the login ticket over plain
   HTTP. Plain-HTTP demo mode leaves `Secure` off, since browsers would drop
   the cookie.
2. The admin bearer token (ADR 0011) is compared as SHA-256 digests in
   constant time instead of with `==`, so timing reveals neither its bytes
   nor its length.

## Consequences

- JWKS and discovery stay cacheable; only the listed endpoints are no-store.
- The CSP sets only `frame-ancestors`; it is not a full content policy for
  the login pages.
