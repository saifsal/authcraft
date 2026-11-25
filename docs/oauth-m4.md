# M4 hardening (PAR + DPoP)

**Status: complete** for the PAR + DPoP + RFC 9700 checklist slice.
Profile: [ADR 0009](adr/0009-hardening-par-dpop.md).
BCP map: [rfc-9700-checklist.md](rfc-9700-checklist.md).

## B1 — PAR

`POST /par` stores authorize parameters and returns `request_uri`.
`GET /authorize?client_id=…&request_uri=…` redeems it once.
Vectors: `testvectors/par/`.

## B2 — DPoP

Optional `DPoP` header on `/token` binds `cnf.jkt` and sets `token_type=DPoP`.
UserInfo requires a matching proof when `cnf` is present.
Vectors: `testvectors/dpop/`.

## Run

```bash
cargo test -p oauth --test vectors
cargo test -p oauth-http
```

## TLS and mutual TLS (ADR 0017)

Serve HTTPS with optional client certificates:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout srv.key -out srv.pem -days 30 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"
AUTHCRAFT_TLS_CERT=srv.pem AUTHCRAFT_TLS_KEY=srv.key cargo run -p oauth-http -- --demo
curl --cacert srv.pem https://localhost:8089/.well-known/openid-configuration
```

A `self_signed_tls_client_auth` client registers its certificate as `x5c` in
`jwks` and then calls `/token` over a connection that presents that
certificate (`curl --cert cli.pem --key cli.key ...`). Any client that
presents a certificate at `/token` without DPoP receives an access token with
`cnf.x5t#S256`. Vectors: `testvectors/mtls/`; real-TLS test:
`rust/crates/oauth-http/tests/mtls.rs`.

For the PKI method (`tls_client_auth`, ADR 0019), also set
`AUTHCRAFT_TLS_CLIENT_CA=client-ca.pem`. Register with
`"token_endpoint_auth_method":"tls_client_auth"` and one of
`tls_client_auth_san_dns`, `_san_uri`, `_san_ip`, or `_san_email`; the client
certificate must be issued directly by that CA and carry the registered SAN.
