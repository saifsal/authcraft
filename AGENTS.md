# authcraft

## Overview

authcraft is an educational OAuth 2.0 / OpenID Connect identity provider. Its purpose is to learn the protocols by implementing the layers underneath them (JOSE, token issuance, verification, and later the OAuth and OIDC flows) and to compare independent implementations of the same security-critical code with a shared test-vector contract. It has had no external review. It is not a production identity provider.

Milestone M0 (JOSE) is complete for the shared-vector contract. The Rust library crate `jose` at `rust/crates/jose` signs and verifies compact JWS/JWT payloads, parses JWK and JWKS documents, computes RFC 7638 thumbprints, and enforces the verifier rules in `docs/adr/0003-verifier-check-order.md`. Generated vectors live under `testvectors/generated/`; compact RFC examples under `testvectors/rfc/`. Zig (`zig/`) and Go (`go/jose`) implement the same verifier; `go/harness` differentials against `jose-cli`. Milestone M1 (`oauth` + `oauth-http`, `testvectors/oauth/`) is complete. M2 OIDC (`testvectors/oidc/`) is complete. M3 token lifecycle (refresh, revoke/introspect, key rotation; ADR 0008, `testvectors/token/`) is complete for the B1–B3 slice. Later milestones (real authentication, control plane, federation) are planned.

M0 verifier work is in place (Rust, Zig, Go, shared vectors, CI, Zig C ABI, `authcraft-edge` sidecar). M1 (`oauth` + `oauth-http`, ADR 0005) and M2 OIDC (ADR 0006) are complete. [`docs/rfc-conformance.md`](docs/rfc-conformance.md) remains the scope map; [`docs/oauth-m1.md`](docs/oauth-m1.md) and [`docs/oauth-m2.md`](docs/oauth-m2.md) cover those slices. Accepted decisions are in [`docs/adr/`](docs/adr/). The milestone list through M8 is in [`README.md`](README.md).

## Repository layout

```
.
├── .github/
│   └── workflows/
│       └── ci.yml                         # Rust/Zig/Go tests + gen-vectors dirty check
├── docs/
│   ├── adr/
│   │   ├── 0001-eddsa-default.md          # EdDSA default; HS256 verify-only; no `none`
│   │   ├── 0002-vectors-are-the-contract.md
│   │   ├── 0003-verifier-check-order.md   # exact check order and error codes
│   │   ├── 0004-zig-c-abi.md              # Zig verify C ABI for embedding
│   │   ├── 0005-oauth-code-pkce.md        # M1 authorization code + PKCE
│   │   ├── 0006-oidc-core-code.md         # M2 OpenID Connect (code + PKCE)
│   │   └── 0007-zig-edge-sidecar.md       # Zig authcraft-edge verify sidecar
│   ├── rfc-conformance.md                 # M0/M1/M2 scope map
│   ├── oauth-m1.md                        # M1 runbook
│   └── oauth-m2.md                        # M2 OIDC runbook
├── rust/
│   ├── Cargo.toml                         # workspace; jose, jose-cli, oauth, oauth-http
│   ├── Cargo.lock
│   ├── mise.toml                          # rust = "stable"
│   ├── crates/jose/
│       ├── Cargo.toml                     # package jose 0.1.0, edition 2021, publish = false
│       ├── src/
│       │   ├── lib.rs                     # #![forbid(unsafe_code)]; module root
│       │   ├── alg.rs                     # EdDSA, ES256, HS256
│       │   ├── b64url.rs                  # strict unpadded canonical base64url
│       │   ├── json.rs                    # strict JSON parser (duplicate keys rejected)
│       │   ├── jwk.rs                     # Ed25519 and P-256 public keys; thumbprints
│       │   ├── jwks.rs                    # JWKS parse and kid selection
│       │   ├── signature.rs               # signature verification
│       │   ├── signing.rs                 # EdDSA and ES256 signing; compact JWS
│       │   └── verify.rs                  # compact JWS/JWT verification and claims
│       ├── tests/thumbprint.rs            # RFC 8037 Appendix A thumbprint vectors
│       └── tests/vectors.rs               # runs testvectors/ against the Rust verifier
│   └── crates/jose-cli/
│       ├── Cargo.toml                     # binary jose-cli (verify, keygen, sign, jwks, gen-vectors)
│       ├── src/main.rs
│       ├── src/gen_vectors.rs             # regenerates testvectors/generated/
│       ├── tests/keygen.rs
│       ├── tests/sign.rs
│       ├── tests/jwks.rs
│       ├── tests/gen_vectors.rs
│       └── tests/verify.rs                # runs jose-cli against testvectors/
│   ├── crates/oauth/
│   │   ├── Cargo.toml                     # package oauth 0.1.0; depends on jose + ring
│   │   ├── src/                           # pkce, client, code, token, id_token, server, error
│   │   └── tests/vectors.rs               # runs testvectors/oauth/ and testvectors/oidc/
│   └── crates/oauth-http/
│       ├── Cargo.toml                     # Axum binary + lib; depends on oauth, jose
│       ├── src/main.rs                    # binds 127.0.0.1:8089
│       ├── src/lib.rs                     # /authorize, /token, /login, JWKS
│       └── tests/e2e.rs                   # authorize → login → token → jose verify
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
│   └── harness/                           # shared vectors + differential vs jose-cli
├── testvectors/
│   ├── generated/                         # ADR 0003 negative and boundary vectors
│   ├── rfc/                               # compact examples copied from RFC 7515 and RFC 8037
│   ├── oauth/                             # M1 PKCE / code-exchange vectors (ADR 0005)
│   ├── oidc/                              # M2 openid / nonce / UserInfo vectors (ADR 0006)
│   └── schema.json                        # JOSE vector schema
├── LICENSE                                # GNU GPL version 3
├── README.md
└── AGENTS.md
```

These paths are described in older notes and are not in the tree: `docs/threat-model.md`. When another language is added, give it its own `mise.toml` in that directory.

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
cargo run -p oauth-http
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

- The tree is the source of truth for what runs. M1 OAuth is Rust-only so far (`oauth` + `oauth-http`); there is no Zig/Go OAuth harness yet. Rust, Zig, and Go JOSE verifiers agree on the shared JOSE vectors; the Go harness differentially checks Go against `jose-cli`.
- `testvectors/generated/` holds the ADR 0003 minimum negative vector set and positive time-boundary cases. `testvectors/rfc/` holds compact examples copied from RFC 7515 and RFC 8037. They are run against Rust (`tests/vectors.rs`), Zig (`zig/src/vectors.zig`), and Go (`go/harness`). The examples whose headers have no `kid` expect `key_not_found`; their signature bytes are checked by `rfc_signatures_match_when_kid_is_absent` in each language. `testvectors/oauth/` is the M1 contract and `testvectors/oidc/` is the M2 contract for the Rust `oauth` crate (ADR 0005 / ADR 0006). Unit tests are not a substitute for those suites; `docs/rfc-conformance.md` says so.
- `cargo test` does start the `oauth-http` e2e harness in-process; `cargo run -p oauth-http` is the interactive demo. There is still no production deployment.
- `docs/threat-model.md` is not in the repository.
- Rust older than 1.88 does not compile `b64url.rs`. A default toolchain of 1.83 fails even though `Cargo.lock` resolves.
- `Jwks::parse` fails the whole document on bad JSON, a missing `keys` array, a non-object entry, a non-string `kid`, or a duplicate `kid`. An entry that is present but unusable (unknown `kty` or `crv`, bad base64url, wrong length, non-string `alg` or `use`, `oct` key under 32 bytes) stays in the set and can never be selected (`key_not_found`). Private members such as `d` are ignored.
- `kid` is required. There is no try-every-key fallback. A key `alg` member must equal the header `alg`. If `alg` is absent, the key type decides: `OKP`/`Ed25519` is `EdDSA`, `EC`/`P-256` is `ES256`, `oct` is `HS256`. A `use` member must be `sig`.
- `exp` is required. `nbf` is optional. When both the expiry and not-before checks fail, the error is `expired`. `typ` comparison strips one leading `application/` and then compares case-insensitively. `iss` and `aud` use exact string equality.
- Ed25519 signatures are deterministic. ES256 signatures are not, so ES256 is tested by round trip. ADR 0001 records that the RFC 7515 ES256 vector is verify-only once vector files exist.
- `PublicKey` checks coordinate lengths. It does not check that a P-256 point is on the curve; `ring` rejects an invalid point at verification time.
- This is unreviewed educational code. Cryptographic primitives come from `ring`; the JOSE layer around them is written here.
