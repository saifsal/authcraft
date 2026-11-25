# authcraft

## Overview

authcraft is an educational OAuth 2.0 / OpenID Connect identity provider. Its purpose is to learn the protocols by implementing the layers underneath them (JOSE, token issuance, verification, and later the OAuth and OIDC flows) and to compare independent implementations of the same security-critical code with a shared test-vector contract. It has had no external review. It is not a production identity provider.

Milestone M0 (JOSE) is complete for the shared-vector contract. The Rust library crate `jose` at `rust/crates/jose` signs and verifies compact JWS/JWT payloads, parses JWK and JWKS documents, computes RFC 7638 thumbprints, and enforces the verifier rules in `docs/adr/0003-verifier-check-order.md`. Generated vectors live under `testvectors/generated/`; compact RFC examples under `testvectors/rfc/`. Zig (`zig/`) and Go (`go/jose`) implement the same verifier; `go/harness` differentials against `jose-cli`. Milestone M1 (`oauth` + `oauth-http`, `testvectors/oauth/`) is complete. M2 OIDC (`testvectors/oidc/`) is complete. M3 token lifecycle (ADR 0008, `testvectors/token/`) is complete for B1–B3. M4 hardening (optional PAR + DPoP, ADR 0009; [RFC 9700 checklist](docs/rfc-9700-checklist.md)) is complete for this slice. M5 authentication (ADR 0010) is complete for this slice: Argon2id passwords, TOTP, and WebAuthn second factors. M6 control plane (ADR 0011) is complete for this slice: admin API, dynamic client registration, and SCIM Users. M7 federation (ADR 0012) is complete for this slice: OIDC RP connector and LDAP MemoryDirectory gateway. M8 assurance (ADR 0013) is complete for this slice: attack harness, cargo-fuzz CI smoke, and an OpenID conformance checklist. Post-M8 hardening continues from the RFC 9700 open list (e.g. RFC 9207 `iss` on authorize redirects; `private_key_jwt` client auth at `/token`, `/par`, `/revoke`, ADR 0014, `testvectors/client_auth/`; JAR request objects, ADR 0015, `testvectors/jar/`; authenticated `/introspect`, ADR 0016, `testvectors/introspect/`; optional HTTPS + RFC 8705 mTLS, ADR 0017, `testvectors/mtls/`; mandatory PAR / DPoP / certificate binding, ADR 0018, `testvectors/enforcement/`; PKI `tls_client_auth`, ADR 0019; redirect URI rules, ADR 0020; HTTP security headers, ADR 0021). Every row of the RFC 9700 checklist is done.

M0 verifier work is in place (Rust, Zig, Go, shared vectors, CI, Zig C ABI, `authcraft-edge` sidecar). M1 (`oauth` + `oauth-http`, ADR 0005) and M2 OIDC (ADR 0006) are complete. [`docs/rfc-conformance.md`](docs/rfc-conformance.md) remains the scope map; [`docs/oauth-m1.md`](docs/oauth-m1.md) and [`docs/oauth-m2.md`](docs/oauth-m2.md) cover those slices. Accepted decisions are in [`docs/adr/`](docs/adr/). The milestone list through M8 is in [`README.md`](README.md).

## Repository layout

```
.
├── .github/
│   └── workflows/
│       └── ci.yml                         # Rust/Zig/Go tests, gen-vectors dirty check, fuzz smoke
├── docs/
│   ├── adr/
│   │   ├── 0001-eddsa-default.md          # EdDSA default; HS256 verify-only; no `none`
│   │   ├── 0002-vectors-are-the-contract.md
│   │   ├── 0003-verifier-check-order.md   # exact check order and error codes
│   │   ├── 0004-zig-c-abi.md              # Zig verify C ABI for embedding
│   │   ├── 0005-oauth-code-pkce.md        # M1 authorization code + PKCE
│   │   ├── 0006-oidc-core-code.md         # M2 OpenID Connect (code + PKCE)
│   │   ├── 0007-zig-edge-sidecar.md       # Zig authcraft-edge verify sidecar
│   │   ├── 0008-token-lifecycle.md        # M3 refresh / revoke / introspect / key rotation
│   │   ├── 0009-hardening-par-dpop.md     # M4 PAR, DPoP, RFC 9207 iss
│   │   ├── 0010-authentication.md         # M5 Argon2id, TOTP, WebAuthn
│   │   ├── 0011-control-plane.md          # M6 admin API, DCR, SCIM
│   │   ├── 0012-federation.md             # M7 OIDC RP, LDAP gateway
│   │   ├── 0013-assurance.md              # M8 attack harness, fuzzing, conformance map
│   │   ├── 0014-private-key-jwt.md        # confidential clients (RFC 7523)
│   │   ├── 0015-jar-request-objects.md    # signed request objects (RFC 9101)
│   │   ├── 0016-protected-introspection.md # authenticated /introspect, resource servers
│   │   ├── 0017-mutual-tls.md             # HTTPS listener, RFC 8705 mTLS
│   │   ├── 0018-enforcement-metadata.md   # mandatory PAR / DPoP / cert binding
│   │   ├── 0019-pki-tls-client-auth.md    # tls_client_auth (CA-issued certs, SAN match)
│   │   ├── 0020-redirect-uri-registration.md # https / loopback / private-use schemes only
│   │   ├── 0021-http-security-headers.md  # framing, referrer, no-store, HSTS
│   │   ├── 0022-second-factor-throttling.md # TOTP lockout + replay protection
│   │   ├── 0023-production-mode.md        # --demo vs production, clients file, key file
│   │   ├── 0024-persistent-accounts.md    # SQLite accounts, email_verified
│   │   ├── 0025-self-service-accounts.md  # sign-up, verify, reset, throttling (from glossa)
│   │   ├── 0026-sso-sessions.md           # SSO session, prompt, /account, logout, tickets
│   │   └── 0027-public-deployment.md      # landing page, Caddy + systemd on the accumu.cc VPS
│   ├── rfc-conformance.md                 # scope map per milestone
│   ├── rfc-9700-checklist.md              # OAuth security BCP status
│   ├── threat-model.md                    # assets, adversaries, mitigations, residual risks
│   ├── openid-conformance-checklist.md    # OIDF-style OP expectations
│   └── oauth-m1.md … oauth-m8.md          # per-milestone runbooks
├── rust/
│   ├── Cargo.toml                         # workspace; jose, jose-cli, oauth, oauth-http
│   ├── Cargo.lock
│   ├── mise.toml                          # rust = "stable"
│   ├── crates/jose/
│   │   ├── Cargo.toml                     # package jose 0.1.0, edition 2021, publish = false
│   │   ├── src/
│   │   │   ├── lib.rs                     # #![forbid(unsafe_code)]; module root
│   │   │   ├── alg.rs                     # EdDSA, ES256, HS256
│   │   │   ├── b64url.rs                  # strict unpadded canonical base64url
│   │   │   ├── json.rs                    # strict JSON parser (duplicate keys rejected)
│   │   │   ├── jwk.rs                     # Ed25519 and P-256 public keys; thumbprints
│   │   │   ├── jwks.rs                    # JWKS parse and kid selection
│   │   │   ├── signature.rs               # signature verification
│   │   │   ├── signing.rs                 # EdDSA and ES256 signing; compact JWS
│   │   │   └── verify.rs                  # compact JWS/JWT verification and claims
│   │   ├── tests/thumbprint.rs            # RFC 8037 Appendix A thumbprint vectors
│   │   └── tests/vectors.rs               # runs testvectors/ against the Rust verifier
│   ├── crates/jose-cli/
│   │   ├── Cargo.toml                     # binary jose-cli (verify, keygen, sign, jwks, gen-vectors)
│   │   ├── src/main.rs
│   │   ├── src/gen_vectors.rs             # regenerates testvectors/generated/
│   │   └── tests/                         # keygen, sign, jwks, gen_vectors, verify
│   ├── crates/oauth/
│   │   ├── Cargo.toml                     # package oauth 0.1.0; jose, ring, argon2, webauthn-rs, rustls-webpki, x509-parser
│   │   ├── src/
│   │   │   ├── server.rs                  # AuthorizationServer: authorize, token, PAR, DCR, admin, SCIM
│   │   │   ├── client.rs                  # Client, TokenEndpointAuth, registry
│   │   │   ├── client_auth.rs             # private_key_jwt assertions (ADR 0014)
│   │   │   ├── request_object.rs          # JAR request objects (ADR 0015)
│   │   │   ├── pkce.rs, code.rs, par.rs   # PKCE, authorization codes, pushed requests
│   │   │   ├── token.rs, id_token.rs      # access token and ID token minting
│   │   │   ├── refresh.rs, denylist.rs    # refresh families, access-token jti denylist
│   │   │   ├── keyring.rs                 # signing-key rotation with grace JWKS
│   │   │   ├── dpop.rs                    # DPoP proofs (RFC 9449)
│   │   │   ├── mtls.rs                    # x5t#S256, x5c registration, tls_client_auth (ADR 0017/0019)
│   │   │   ├── users.rs, totp.rs, webauthn_mfa.rs # resource-owner authentication
│   │   │   ├── scim.rs                    # SCIM 2.0 Users
│   │   │   ├── federation/                # oidc_rp.rs, ldap.rs
│   │   │   └── error.rs, lib.rs
│   │   └── tests/
│   │       ├── vectors.rs                 # runs every OAuth testvectors/ directory
│   │       └── attack_harness.rs          # protocol attack negatives (ADR 0013)
│   ├── crates/oauth-http/
│   │   ├── Cargo.toml                     # Axum binary + lib; oauth, jose, rusqlite (bundled), clap
│   │   ├── src/main.rs                    # binds 127.0.0.1:8089; HTTPS when AUTHCRAFT_TLS_* set
│   │   ├── src/lib.rs                     # HTTP routes for every endpoint
│   │   ├── src/tls.rs                     # rustls listener, optional client certs (ADR 0017)
│   │   ├── src/config.rs                  # clients file, signing-key file, secrets (ADR 0023)
│   │   ├── src/store.rs                   # SQLite: users, auth_tokens, outbox (ADR 0024/0025)
│   │   ├── src/accounts.rs                # sign-up / verify / reset flows + pages (ADR 0025)
│   │   ├── src/mailer.rs                  # outbox + Resend worker (ported from glossa)
│   │   ├── src/ratelimit.rs, src/pages.rs # fixed-window limits; shared HTML layout
│   │   ├── src/session.rs                 # SSO sessions + expiring login tickets (ADR 0026)
│   │   ├── assets/                        # favicon.svg (source), favicon.ico, make-favicon.py
│   │   ├── tests/e2e.rs                   # authorize → login → token → jose verify
│   │   ├── tests/confidential.rs          # private_key_jwt + JAR + introspect over HTTP
│   │   ├── tests/mtls.rs                  # self-signed mTLS + bound tokens over real TLS
│   │   ├── tests/accounts.rs              # sign-up → verify → code; reset; throttling
│   │   ├── tests/sso.rs                   # session reuse, prompt, logout, reset ends sessions
│   │   └── tests/landing.rs               # landing page lists configured apps
│   └── fuzz/                              # cargo-fuzz targets (own Cargo.lock; not in workspace)
│       └── fuzz_targets/                  # b64url_decode, json_parse, jose_verify, pkce_challenge
├── zig/
│   ├── mise.toml                          # zig = "0.14.1"
│   ├── build.zig
│   ├── build.zig.zon                      # package jose 0.1.0
│   ├── include/
│   │   └── authcraft_jose.h               # C ABI header (ADR 0004)
│   └── src/
│       ├── root.zig                       # module root
│       ├── alg.zig                        # EdDSA, ES256, HS256
│       ├── b64url.zig                     # strict unpadded canonical base64url
│       ├── json.zig                       # strict JSON (duplicate keys rejected)
│       ├── jwk.zig                        # Ed25519 and P-256 public keys; thumbprints
│       ├── jwks.zig                       # JWKS parse and kid selection
│       ├── policy.zig                     # jose-cli-compatible policy JSON
│       ├── signature.zig                  # EdDSA, ES256, HS256 verification
│       ├── verify.zig                     # compact JWS/JWT verification and claims
│       ├── c_api.zig                      # authcraft_jose_verify export
│       ├── sidecar_verify.zig             # Bearer + C ABI wiring (ADR 0007)
│       ├── sidecar.zig                    # authcraft-edge HTTP binary
│       └── vectors.zig                    # runs testvectors/ against the Zig verifier
├── go/
│   ├── mise.toml                          # go = "1.27.4"
│   ├── go.mod                             # module github.com/saifsal/authcraft/go
│   ├── jose/                              # compact JWS/JWT verifier (stdlib crypto)
│   └── harness/
│       ├── vectors_test.go                # JOSE vectors + differential vs jose-cli
│       └── oauth_jwt_test.go              # JWT layer of client_auth/jar/introspect vectors
├── testvectors/
│   ├── README.md
│   ├── schema.json                        # JOSE vector schema
│   ├── generated/                         # ADR 0003 negative and boundary vectors
│   ├── rfc/                               # compact examples copied from RFC 7515 and RFC 8037
│   ├── oauth/                             # M1 PKCE / code exchange (ADR 0005)
│   ├── oidc/                              # M2 openid / nonce / UserInfo (ADR 0006)
│   ├── token/                             # M3 refresh / revoke / introspect (ADR 0008)
│   ├── par/, dpop/                        # M4 PAR and DPoP (ADR 0009)
│   ├── authn/                             # M5 password / TOTP (ADR 0010)
│   ├── admin/, dcr/                       # M6 admin API and registration (ADR 0011)
│   ├── client_auth/                       # private_key_jwt (ADR 0014)
│   ├── jar/                               # request objects (ADR 0015)
│   ├── introspect/                        # introspection callers (ADR 0016)
│   ├── mtls/                              # RFC 8705 client auth and binding (ADR 0017)
│   └── enforcement/                       # mandatory PAR / sender-constraint (ADR 0018)
├── deploy/                                # Caddyfile, authcraft.service, clients.example.json, runbook
├── mise.toml                              # repo tasks: build-release, deploy (never run by agents)
├── LICENSE                                # GNU GPL version 3
├── README.md
└── AGENTS.md
```

When another language is added, give it its own `mise.toml` in that directory.

## Setup

Prerequisites:

- Rust stable, 1.88 or newer. `slice::as_chunks` is used in `rust/crates/jose/src/b64url.rs`. Rust 1.83 fails to compile the crate with `E0658` (`slice_as_chunks` still unstable). `rust/mise.toml` pins `rust = "stable"`.
- A C compiler. `ring` 0.17 builds native code (used by `jose` and `oauth`). `oauth-http` also pulls Axum/Tokio.
- Network access on the first build, to fetch the crates.io packages locked in `rust/Cargo.lock`.
- Zig 0.14.1 for the `zig/` package. `zig/mise.toml` pins `zig = "0.14.1"`.
- Go 1.27.4 for the `go/` package. `go/mise.toml` pins `go = "1.27.4"`.

With [mise](https://mise.jdx.dev/) installed, from a shell where mise is activated:

```bash
cd rust && mise install
cd ../zig && mise install
cd ../go && mise install
```

`mise` was not installed in the environment used to check this repository historically. The Rust commands below were run with rustup's stable toolchain (`rustc 1.99.0`) as `cargo +stable …` from `rust/` when the default was 1.83.0. Use whichever `cargo` is actually stable 1.88 or newer. The Zig commands were run with `mise exec --` from `zig/` (`zig 0.14.1`). The Go commands were run with `mise exec --` from `go/` (`go 1.27.4`).

## Build, run and test

JOSE crates are libraries (`publish = false`). M1/M2 use `oauth` (library) and `oauth-http` (Axum demo server on `127.0.0.1:8089`). Zig ships the verifier library, C ABI, and `authcraft-edge` (default `127.0.0.1:8091`). Go remains a verifier + harness.

From `rust/`, with stable Rust on `PATH`:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo run -p oauth-http -- --demo
```

`cargo test --workspace` and Clippy with `-D warnings` must pass on stable. That suite includes `jose`, `jose-cli`, `oauth` (including `testvectors/oauth/` and `testvectors/oidc/`), and `oauth-http` e2e. See [`docs/oauth-m1.md`](docs/oauth-m1.md) and [`docs/oauth-m2.md`](docs/oauth-m2.md).

From `zig/`:

```bash
mise exec -- zig build test
```

That command succeeded on Zig 0.14.1 and runs the library unit tests (including the C ABI and sidecar verify wiring), plus the shared-vector suite in `src/vectors.zig` (cwd is the `zig/` package directory, which resolves `../testvectors`). `zig build` installs `libjose.a`, `libauthcraft_jose.so`, and `include/authcraft_jose.h` under `zig-out/`. `zig build sidecar` (or a full `zig build`) installs `authcraft-edge`:

```bash
mise exec -- zig build sidecar
./zig-out/bin/authcraft-edge --jwks jwks.json --policy policy.json
```

From `go/`:

```bash
mise exec -- go test ./...
```

That command succeeded on Go 1.27.4. `jose` unit tests and `harness` shared-vector tests always run. `TestDifferentialAgainstJoseCLI` also runs when `../rust/target/debug/jose-cli` (or `AUTHCRAFT_JOSE_CLI`) exists; otherwise it skips.

Run one integration test, or that test file:

```bash
cargo test -p jose rfc8037_a3_thumbprint
cargo test -p jose --test thumbprint -- rfc8037_a3_thumbprint
cargo test -p jose --test thumbprint
```

The first command filters every target by that name, so the library unit tests report zero matches and `tests/thumbprint.rs` runs `rfc8037_a3_thumbprint`. That is what happened when the command was run.

`cargo fmt --all -- --check` is not a clean gate today. There is no `rustfmt.toml`, and rustfmt reports diffs in existing sources. Do not reformat unrelated code while changing behavior.

## Code style and conventions

- Edition 2021. The crate root is `#![forbid(unsafe_code)]`.
- The only dependency is `ring`. Hashes, Ed25519, ECDSA P-256, and HMAC come from `ring`. JOSE parsing, canonical base64url, JSON, key selection, and claim checks are written in this crate. There is no `serde` and no `zeroize` dependency.
- JSON object member names are unique after unescaping. The hand-written parser exists so duplicate keys are errors. `exp` and `nbf` are accepted only as integer JSON numbers that fit in `i64` (`json::Number::Int`).
- Base64url is unpadded. A segment must be the canonical encoding: unused trailing bits are zero. The decoder is not constant-time and is for token text, not secret key material.
- Public error types implement `Display` and `std::error::Error`. `verify::VerifyError::code` returns the stable strings in `docs/adr/0003-verifier-check-order.md` (`malformed`, `too_large`, `alg_not_allowed`, `crit_unsupported`, `typ_mismatch`, `key_not_found`, `bad_signature`, `expired`, `not_yet_valid`, `wrong_issuer`, `wrong_audience`).
- `Alg` is `EdDSA`, `ES256`, and verify-only `HS256`. `none` is not a variant. Algorithm names match case-sensitively.
- Verification follows `docs/adr/0003-verifier-check-order.md`: size and shape, then the algorithm allowlist, then `typ` and `kid` selection, then the signature, then payload parsing and claims. The signature is checked before the payload is parsed. Keys come from the `Jwks` passed by the caller. Header `jku`, `jwk`, `x5u`, `x5c`, and `x5t` are not consulted.
- ES256 signatures are the 64-byte JOSE `R || S` form. HS256 signing returns `SigningError::UnsupportedAlgorithm`. HS256 keys shorter than 32 bytes are rejected.
- Module docs name the RFC or ADR they implement. Tests live in `#[cfg(test)]` modules next to the code, plus `rust/crates/jose/tests/thumbprint.rs` and `tests/vectors.rs` (the shared-vector runner; it re-serializes each vector's `jwks` with a test-local JSON writer because the crate has no serializer).
- `Policy.now` is an explicit Unix timestamp. Tests do not read the wall clock.
- History uses [Conventional Commits](https://www.conventionalcommits.org/), with scopes such as `feat(rust):`, `fix(rust):`, `refactor(rust):`, and `docs:`.

## CI and tooling

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on pushes and pull requests to `main`:

- Rust: `cargo test --workspace`, Clippy with `-D warnings`, build `jose-cli`, then `jose-cli gen-vectors --out testvectors/generated` and `git diff --exit-code` (ADR 0002).
- Zig: `zig build test` on Zig 0.14.1.
- Go: `go test ./...` with `AUTHCRAFT_JOSE_CLI` pointing at the Rust-built `jose-cli` artifact (shared vectors plus differential).

Local tooling:

- `rust/mise.toml` pins Rust to the stable channel; `zig/mise.toml` pins Zig 0.14.1; `go/mise.toml` pins Go 1.27.4.
- `rust/Cargo.lock` is committed.
- Clippy, as invoked in [Build, run and test](#build-run-and-test), passes with `-D warnings` on stable.
- rustfmt is not enforced. See the `cargo fmt` note above.

## Working rules for agents

- Keep changes small and focused.
- Run the tests before committing. From `rust/`, `cargo test --workspace` on stable Rust is the suite that exists today. Run `cargo clippy --all-targets --all-features -- -D warnings` when the change touches Rust.
- Never commit secrets. `testvectors/` is for published test keys only. Do not put real private keys, tokens, or credentials in the tree.
- Update the docs when behaviour changes. That includes `README.md`, `docs/rfc-conformance.md`, and any ADR whose decision changed. A new verifier check needs a row in `docs/adr/0003-verifier-check-order.md` and, once the vector suite exists, a case under `testvectors/` whose expected error code matches exactly.
- Use conventional commit messages.
- Read `docs/rfc-conformance.md` and the relevant ADR before changing validation, signing, or thumbprints. The vector schema in `testvectors/schema.json` and ADR 0002 are the contract between implementations, including implementations that are not written yet. Fix the implementation when it disagrees with a vector, unless the vector is shown to be wrong against the specification.
- Preserve `#![forbid(unsafe_code)]`.

## Gotchas

- The tree is the source of truth for what runs. M1 OAuth is Rust-only so far (`oauth` + `oauth-http`); there is no Zig/Go OAuth harness yet. Rust, Zig, and Go JOSE verifiers agree on the shared JOSE vectors; the Go harness differentially checks Go against `jose-cli`. `go/harness/oauth_jwt_test.go` re-verifies the JWTs in `testvectors/client_auth/`, `jar/`, and `introspect/` at the JWT layer only; its `jwtVerdicts` table must classify every vector file in those directories.
- `testvectors/generated/` holds the ADR 0003 minimum negative vector set and positive time-boundary cases. `testvectors/rfc/` holds compact examples copied from RFC 7515 and RFC 8037. They are run against Rust (`tests/vectors.rs`), Zig (`zig/src/vectors.zig`), and Go (`go/harness`). The examples whose headers have no `kid` expect `key_not_found`; their signature bytes are checked by `rfc_signatures_match_when_kid_is_absent` in each language. `testvectors/oauth/` is the M1 contract and `testvectors/oidc/` is the M2 contract for the Rust `oauth` crate (ADR 0005 / ADR 0006). Unit tests are not a substitute for those suites; `docs/rfc-conformance.md` says so.
- `cargo test` does start the `oauth-http` e2e harness in-process; `cargo run -p oauth-http -- --demo` is the interactive demo; without `--demo` the binary needs `--data-dir` and `--public-url` (production mode, ADR 0023) and refuses to start otherwise. Set `AUTHCRAFT_TLS_CERT` and `AUTHCRAFT_TLS_KEY` to PEM files to serve HTTPS (optional mTLS) instead, and `AUTHCRAFT_TLS_CLIENT_CA` to trust a CA for `tls_client_auth`; `tests/mtls.rs` starts a real TLS listener on an ephemeral loopback port. There is still no production deployment.
- `docs/threat-model.md` is the threat model. Update it when a change adds an endpoint, credential, token type, or trust boundary, or closes one of its residual risks.
- Rust older than 1.88 does not compile `b64url.rs`. A default toolchain of 1.83 fails even though `Cargo.lock` resolves.
- `Jwks::parse` fails the whole document on bad JSON, a missing `keys` array, a non-object entry, a non-string `kid`, or a duplicate `kid`. An entry that is present but unusable (unknown `kty` or `crv`, bad base64url, wrong length, non-string `alg` or `use`, `oct` key under 32 bytes) stays in the set and can never be selected (`key_not_found`). Private members such as `d` are ignored.
- `kid` is required. There is no try-every-key fallback. A key `alg` member must equal the header `alg`. If `alg` is absent, the key type decides: `OKP`/`Ed25519` is `EdDSA`, `EC`/`P-256` is `ES256`, `oct` is `HS256`. A `use` member must be `sig`.
- `exp` is required. `nbf` is optional. When both the expiry and not-before checks fail, the error is `expired`. `typ` comparison strips one leading `application/` and then compares case-insensitively. `iss` and `aud` use exact string equality.
- Ed25519 signatures are deterministic. ES256 signatures are not, so ES256 is tested by round trip. ADR 0001 records that the RFC 7515 ES256 vector is verify-only once vector files exist.
- `PublicKey` checks coordinate lengths. It does not check that a P-256 point is on the curve; `ring` rejects an invalid point at verification time.
- This is unreviewed educational code. Cryptographic primitives come from `ring`; the JOSE layer around them is written here.
