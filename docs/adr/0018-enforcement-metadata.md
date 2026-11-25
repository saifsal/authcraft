# ADR 0018: Mandatory PAR and sender-constrained tokens

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

PAR (ADR 0009), DPoP (ADR 0009), and mTLS binding (ADR 0017) were optional:
a client could always fall back to front-channel parameters and bearer
tokens. Only PAR had a switch, and it was server-wide. RFC 9700 §2.1 and
§2.2 recommend sender-constrained tokens, and the specifications define client
metadata that lets the AS make each mechanism mandatory per client:

- `require_pushed_authorization_requests` (RFC 9126 §6),
- `dpop_bound_access_tokens` (RFC 9449 §5.2),
- `tls_client_certificate_bound_access_tokens` (RFC 8705 §3.4).

## Decision

1. `Client.policy: ClientPolicy` holds those three flags (default `false`).
   They can be set through RFC 7591 registration and `POST /admin/clients`,
   using the RFC metadata names, and are echoed in both responses.
2. `require_pushed_authorization_requests`: front-channel authorize parameters
   (including a front-channel JAR `request`) are `invalid_request`; only a PAR
   `request_uri` is accepted. Server-wide `require_par` is unchanged.
3. `dpop_bound_access_tokens`: a token request (either grant) without a DPoP
   proof is `invalid_request`.
4. `tls_client_certificate_bound_access_tokens`: a token request without a TLS
   client certificate, or with a DPoP proof as well, is `invalid_request`
   (DPoP takes precedence under ADR 0017, so it would replace the certificate
   binding).
5. A client cannot set both binding flags (`invalid_request` at
   registration).
6. `ServerConfig.require_sender_constrained_tokens` (default `false`): every
   token request needs a DPoP proof or a TLS client certificate.
7. These checks run after client authentication and before any DPoP nonce
   rotation, code redemption, or refresh rotation, so a refused request
   consumes nothing and a compliant retry succeeds.
8. Vectors: `testvectors/enforcement/` and registration cases in
   `testvectors/dcr/`.

## Consequences

- The RFC 9700 PAR and sender-constraint rows are enforceable per client or
  server-wide. The demo keeps every flag off so the M1–M4 walkthroughs work.
- `Client`, `DynamicClientRequest`, and `DynamicClientSuccess` gain `policy`;
  `DynamicClientRequest` derives `Default`.
