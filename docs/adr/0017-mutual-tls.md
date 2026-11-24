# ADR 0017: TLS listener and OAuth mutual TLS (RFC 8705)

- **Status:** Accepted (amended as slices land)
- **Date:** 2026-11-25

## Context

`oauth-http` served plain HTTP on `127.0.0.1:8089`. RFC 9700 expects TLS
everywhere and lists mutual TLS (RFC 8705) as one way to authenticate clients
and sender-constrain tokens. ADR 0014 added `private_key_jwt`; ADR 0009 added
DPoP. mTLS is the remaining RFC 9700 mechanism, and it needs a TLS listener.

## Decision

### Transport (`oauth-http`)

1. Optional HTTPS: with `AUTHCRAFT_TLS_CERT` and `AUTHCRAFT_TLS_KEY` (PEM
   paths) set, the binary serves TLS on `127.0.0.1:8089` with issuer
   `https://localhost:8089`. Without them it serves plain HTTP as before.
2. rustls (ring provider) asks every client for a certificate but does not
   require one. Client certificates are not chain-validated (RFC 8705 §2.2
   self-signed method); rustls still verifies the handshake signature, so the
   client must hold the private key.
3. `tls::serve_tls` puts the leaf certificate's DER bytes in a per-connection
   `TlsClientCert` request extension. Plain HTTP never sets it, so a request
   header cannot claim a certificate.

### Protocol (`oauth`, transport-agnostic)

4. `TokenEndpointAuth::SelfSignedTlsClientAuth { cert_thumbprints }`
   (`self_signed_tls_client_auth`). Registration (`/register`,
   `/admin/clients`) takes a `jwks` whose keys carry `x5c`; the `x5t#S256`
   of each key's first certificate is stored. The client authenticates at
   `/token`, `/par`, `/revoke`, and `/introspect` by presenting one of those
   certificates. No certificate, another certificate, or an additional client
   assertion is `invalid_client`. JAR (`require_signed_request_object`) still
   needs `private_key_jwt`.
5. Certificate-bound tokens (RFC 8705 §3): when `/token` sees a client
   certificate and no DPoP proof, the access token gets
   `cnf: {"x5t#S256": ...}` and the refresh family stores the thumbprint.
   This applies to every client type, including public clients (§4). With a
   DPoP proof too, DPoP binds and no `x5t#S256` is added. `token_type` stays
   `Bearer` for certificate-bound tokens.
6. UserInfo rejects a certificate-bound token unless the connection presents
   the same certificate (`invalid_token`). Refreshing a bound family with a
   different or missing certificate is `invalid_grant`, checked before the
   refresh token is rotated.
7. Library API: `exchange_token_tls` and `userinfo_tls` take the client
   certificate; `exchange_token` and `userinfo` call them with `None`.
   `ClientAssertion` is renamed `ClientCredentials` and gains
   `tls_client_cert`.
8. Discovery: `self_signed_tls_client_auth` in the token, revocation, and
   introspection auth-method lists, and
   `tls_client_certificate_bound_access_tokens: true`.
9. Vectors: `testvectors/mtls/` (two self-signed Ed25519 test certificates
   in its schema) and registration cases in `testvectors/dcr/`.
   `oauth-http/tests/mtls.rs` runs the flow over real TLS with `rcgen`
   certificates.

## Amendments

### B2 — Binding in introspection responses

1. Active introspection responses include `cnf` when the token is bound:
   `{"jkt": ...}` for DPoP (RFC 9449 §6.2) and `{"x5t#S256": ...}` for mTLS
   (RFC 8705 §3.2). Refresh tokens report their family's binding.
2. A DPoP-bound access token is reported with `token_type: "DPoP"`
   (previously `Bearer`); certificate-bound tokens stay `Bearer`.
3. `Introspection` gains `cnf_jkt` and `cnf_x5t_s256`.

## Not in this slice

- `tls_client_auth` (PKI method: CA chain plus subject DN or SAN matching).
- `mtls_endpoint_aliases`; the same endpoints serve TLS and mTLS.
- TLS for `authcraft-edge` (Zig) and production hardening (certificate
  reload, HSTS, non-loopback binds).

## Consequences

- The RFC 9700 TLS row moves from open to partial (local demo listener), and
  mTLS client authentication / sender-constrained tokens are available.
- `RefreshRecord` gains `mtls_x5t`; `TokenClaims` gains `cnf_x5t_s256`.
