# RFC conformance

This document defines the intended M0 JOSE scope and tracks the evidence for
each area. Implementation-level conformance for an item requires shared vectors
that exercise the behavior and agreement from every implemented verifier on the
expected result, as required by ADR 0002. Rust, Zig, and Go currently satisfy
that bar for the M0 checks listed below; CI regenerates the generated vector
set and re-runs the three suites.

**Implemented** below means Rust code exists for the listed behavior; it does not
mean that the behavior has passed the shared-vector suite. Unit tests are useful
implementation evidence, but are not a substitute for that suite.

## M0 scope

M0 covers JWS compact serialization, a deliberately small signing and
verification algorithm set, JWK/JWKS handling, RFC 7638 thumbprints, and the
JWT claims needed for the project's token profile. It does not aim to implement
all of JOSE or all JWT claims and profiles.

| Specification | In-scope sections and behavior | Current evidence / remaining work |
|---|---|---|
| RFC 7515, JWS | Compact JWS parsing, signing, and verification; protected-header handling; signing input is the ASCII `BASE64URL(protected).BASE64URL(payload)` bytes | Rust, Zig, and Go compact verification exist for JSON JWT payloads; Rust also signs. Compact examples from Appendix A.1–A.5 and Appendix E are in `testvectors/rfc/` with ADR 0003 verdicts; A.1 and A.3 stop at `key_not_found` before the signature. All three verifiers agree on the shared suite; Go also differentials against `jose-cli`. JSON JWS serialization and detached payloads are out of scope. |
| RFC 7517, JWK | Public `OKP`/`Ed25519` and `EC`/`P-256` keys; `oct` keys only for HS256 verification | Rust, Zig, and Go parse these key types for the verifier. Private-key import/export, key use beyond signature verification, and other key types are out of scope. |
| RFC 7517, JWKS | Parse a configured `keys` array and select one key by exact `kid` | Rust, Zig, and Go parsing and selection exist. Duplicate `kid` is a configuration error; there is no token-directed key fetching or fallback search. `jose-cli jwks` builds a JWKS from keygen or bare JWK inputs and validates it with the same parser. |
| RFC 7518, JWA | HS256 verification only; ES256 verification with P-256 and fixed-width 64-byte signatures formed by concatenating the 32-byte R and S values | Rust, Zig, and Go enforce the 256-bit minimum HS256 key length in JWKS parsing and signature verification. The Appendix A.1 HMAC and Appendix A.3 ES256 signature are checked by each language's signature test because the shared verdicts return at `key_not_found`. |
| RFC 7638, JWK thumbprints | SHA-256 thumbprints for public Ed25519 and P-256 keys using the required canonical public members | Rust, Zig, and Go implementations and RFC-derived unit tests exist. Thumbprints for `oct` and other key types are out of scope. |
| RFC 8032, Ed25519 | Ed25519 signature verification primitive used by JOSE EdDSA | Rust uses `ring`; Zig uses `std.crypto.sign.Ed25519`; Go uses `crypto/ed25519`. All three agree on the RFC 8037 Appendix A.4 signature check. |
| RFC 8037, OKP / EdDSA | Ed25519 represented as `OKP`/`Ed25519` and used with JOSE `EdDSA` | Rust key parsing, signing, and verification exist; Zig and Go verify. Appendix A.4 is `testvectors/rfc/rfc8037-a4-eddsa.json` and is `key_not_found` (no `kid`); each language's signature test checks that signature. |
| RFC 7519, JWT | `iss`, `aud`, `exp`, and `nbf` checks needed by this project; integer NumericDate values only | Rust, Zig, and Go claims validation exist. This profile deliberately requires `exp`, requires `kid` for selection, rejects fractional NumericDates, and checks issuer/audience only when configured. These are project restrictions, not general JWT requirements. |
| RFC 8725, JWT BCP | Algorithm allowlisting, issuer/audience validation when configured, explicit typing when configured, and parsing the payload only after signature verification | These decisions are specified in ADR 0003 and implemented in the Rust, Zig, and Go verifiers. This does not claim full RFC 8725 conformance. |
| RFC 9068, JWT Profile for OAuth 2.0 Access Tokens | `at+jwt` typing is supported by the verifier's configurable `typ` check | Full access-token profile validation is not in M0. Required profile claims and authorization-server behavior belong with the OAuth/OIDC milestones. |

## Deliberate restrictions and exclusions

- The accepted algorithms are EdDSA (Ed25519) and ES256, with HS256 available
  only for verification and never in the default allowlist. `none` is not
  supported. See [ADR 0001](adr/0001-eddsa-default.md).
- RSA/RS256 is not part of the baseline M0 scope. The ADR records it as a
  possible Rust-only stretch goal; it is not implemented by the current Rust
  algorithm set.
- JWE, JWS JSON serialization, detached payloads, general key management, and
  unlisted JWS algorithms are out of scope.
- Header `crit` extensions are not supported. A present `crit` value must be a
  non-empty array of strings, then the token is rejected as unsupported.
- A verifier uses only the configured JWKS. It never follows `jku` or `x5u`,
  nor trusts embedded `jwk` or certificate-chain header values.
- Duplicate JSON member names are rejected. Base64url is unpadded and canonical.
- The claim profile and check order, including project-specific deviations, are
  specified in [ADR 0003](adr/0003-verifier-check-order.md).

## M1 OAuth (authorization code + PKCE)

Profile: [ADR 0005](adr/0005-oauth-code-pkce.md). Narrative: [oauth-m1.md](oauth-m1.md).

| Specification | In-scope behavior | Evidence |
|---|---|---|
| RFC 6749 §4.1 | Authorization code grant; public clients; `/authorize` + `/token` | `rust/crates/oauth`, `oauth-http` e2e test |
| RFC 7636 | S256 PKCE required; `plain` rejected; verifier length/charset | `testvectors/oauth/` + `oauth` tests (incl. RFC Appendix B challenge) |
| RFC 9068 (partial) | Access tokens are `at+jwt` with `iss`/`aud`/`exp`/`sub` | Minted by `oauth`, verified with M0 `jose` |

## M2 OpenID Connect (code + PKCE)

Profile: [ADR 0006](adr/0006-oidc-core-code.md). Narrative: [oauth-m2.md](oauth-m2.md).

| Specification | In-scope behavior | Evidence |
|---|---|---|
| OIDC Core §3.1 | `openid` scope → ID token; `nonce` required; code flow only | `testvectors/oidc/` + `oauth` / `oauth-http` tests |
| OIDC Core §3.1.3.6 | `at_hash` for EdDSA (SHA-256 left half) | `oauth::id_token::at_hash_eddsa` + vectors |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | `oauth-http` |
| OIDC UserInfo | Bearer `at+jwt` → `{sub, name?, email?}` | `AuthorizationServer::userinfo` + e2e |

## M3 token lifecycle

Profile: [ADR 0008](adr/0008-token-lifecycle.md). Narrative: [oauth-m3.md](oauth-m3.md).

| Specification | In-scope behavior | Evidence |
|---|---|---|
| RFC 6749 §6 | `refresh_token` grant; rotation; reuse → `invalid_grant` | `testvectors/token/` + `oauth` tests |
| RFC 7009 | `POST /revoke`; refresh family / access `jti` denylist | `AuthorizationServer::revoke` + vectors |
| RFC 7662 | `POST /introspect` (`active` + claims); no client auth (demo) | `AuthorizationServer::introspect` |

## Other RFCs referenced by the project

These specifications inform later milestones or provide context:

| Specification | Planned relevance |
|---|---|
| RFC 9700, OAuth 2.0 Security BCP | Later OAuth hardening milestone (M4) |

## Checked-in RFC vectors

`testvectors/rfc/` copies compact serializations from the RFC text. The
expected verdict is the ADR 0003 code for this profile.

- RFC 7515 Appendix A.1 (HS256) and Appendix A.3 (ES256), and RFC 8037
  Appendix A.4 (EdDSA), have no `kid`. The shared result is `key_not_found`.
  `rfc_signatures_match_when_kid_is_absent` in
  `rust/crates/jose/tests/vectors.rs`, `zig/src/vectors.zig`, and
  `go/harness` checks those published signatures against the keys in the same
  files.
- RFC 7515 Appendix A.2 (`RS256`) and Appendix A.4 (`ES512`) are
  `alg_not_allowed`. Appendix A.5 (`none`) and Appendix E (crit, unsecured)
  are `malformed` because the signature segment is empty. Those checks happen
  before key lookup.
- JSON serialization examples (RFC 7515 Appendix A.6 and A.7) and detached
  payloads are not in this directory.

Rust, Zig, and Go agree on these files. The Go harness also compares Go
verdicts to `jose-cli` (ADR 0002).

## Completion criteria

Do not mark an item fully conformant based only on implementation or unit
tests. For M0, record the RFC-derived or generated shared vectors that exercise
the item, run them against every implemented verifier, and resolve all
disagreements according to [ADR 0002](adr/0002-vectors-are-the-contract.md).
Update this map when a scope decision changes or a known gap is closed.
