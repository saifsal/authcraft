# ADR 0021: HTTP security headers

- **Status:** Accepted
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

## Consequences

- JWKS and discovery stay cacheable; only the listed endpoints are no-store.
- The CSP sets only `frame-ancestors`; it is not a full content policy for
  the login pages.
