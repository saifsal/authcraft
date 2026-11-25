# ADR 0019: PKI mutual-TLS client authentication (`tls_client_auth`)

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

ADR 0017 implemented RFC 8705 §2.2 (`self_signed_tls_client_auth`), where the
client registers the exact certificate it will present. RFC 8705 §2.1 defines
the other method: the client holds a certificate from a CA the AS trusts and
registers one expected subject, so it can renew the certificate without
re-registering. The RFC 9700 checklist listed it as the missing client
authentication method.

## Decision

1. `ServerConfig.tls_client_auth_trust_anchors`: DER CA certificates trusted
   for client certificates. Empty (the default) disables the method:
   registration with `tls_client_auth` is `invalid_request`. The binary loads
   them from `AUTHCRAFT_TLS_CLIENT_CA` (PEM) in HTTPS mode.
2. `TokenEndpointAuth::TlsClientAuth { subject }`, registered through RFC 7591
   or the admin API with `token_endpoint_auth_method: "tls_client_auth"` and
   exactly one of `tls_client_auth_san_dns` (case-insensitive),
   `tls_client_auth_san_uri`, `tls_client_auth_san_ip` (compared as
   octets), or `tls_client_auth_san_email` (exact). Two or more, or a subject
   member with another auth method, is `invalid_request`.
3. `tls_client_auth_subject_dn` is refused (`invalid_request`). RFC 8705 asks
   for RFC 4517 distinguishedNameMatch; a string comparison would accept or
   reject the wrong certificates, so it is left out rather than approximated.
4. Authentication (at `/token`, `/par`, `/revoke`, `/introspect`): the TLS
   connection must present a client certificate and no client assertion.
   `rustls-webpki` verifies the leaf against the trust anchors at the
   request's `now`, checking the signature, validity period, and the clientAuth
   extended key usage when the certificate declares extended key usages. The
   leaf must be issued directly by an anchor; intermediates are not passed
   through yet. Then `x509-parser` reads the SANs and one must equal the
   registered subject. Any failure is `invalid_client`.
5. The TLS listener is unchanged: it still accepts any client certificate
   whose handshake signature verifies (ADR 0017). The AS, not the TLS layer,
   decides trust, so self-signed and PKI clients share one listener.
6. Tokens are certificate-bound exactly as in ADR 0017 (`cnf.x5t#S256` of the
   presented leaf), and the ADR 0018 enforcement flags apply.
7. Discovery lists `tls_client_auth` in the token, revocation, and
   introspection auth-method lists.
8. Vectors: PKI cases in `testvectors/mtls/` (a test CA and three leaves in
   its schema: trusted clientAuth, untrusted issuer, serverAuth-only) and
   registration cases in `testvectors/dcr/`. `oauth-http/tests/mtls.rs` runs
   the method over real TLS with `rcgen` certificates.

## Not in this slice

- Subject DN matching and intermediate CA chains.
- Revocation checking (CRL, OCSP).

## Consequences

- The `oauth` crate depends directly on `rustls-webpki`, `rustls-pki-types`,
  and `x509-parser`, which were already in the lockfile.
- With ADR 0014 and ADR 0017, every RFC 9700 §2.5 asymmetric client
  authentication method is available.
