# ADR 0013: M8 assurance (attack harness, fuzzing, conformance map)

- **Status:** Accepted (amended as M8 slices land)
- **Date:** 2026-11-22

## Context

M0–M7 implement an educational AS and JOSE stack. Assurance work should prove
negative cases stay rejected, parsers do not panic on garbage, and OpenID
conformance expectations are tracked even when the full external suite is not
wired into CI.

## Decision — B1: attack harness

1. Library integration tests in `oauth/tests/attack_harness.rs` exercise classic
   protocol attacks against `AuthorizationServer` (and jose where relevant).
2. Each case asserts a stable error code (OAuth / authn / verify), not merely
   “err”.
3. Cases cover at least: PKCE `plain`, redirect mismatch, authorization-code
   replay, token `client_id` mismatch, missing OIDC `nonce`, refresh reuse,
   DPoP-bound UserInfo without proof, admin without bearer.

## Amendments

### B2 — fuzzing

1. `rust/fuzz/` cargo-fuzz targets (excluded from the workspace members):
   `b64url_decode`, `json_parse`, `jose_verify`, `pkce_challenge`.
2. CI job `fuzz-smoke` on nightly runs each target for 15 seconds.
3. Stable companion: `jose/tests/parser_smoke.rs` feeds garbage without nightly.

### B3 — OpenID conformance checklist

1. [`docs/openid-conformance-checklist.md`](../openid-conformance-checklist.md)
   maps Basic OP–style expectations to done/partial/open.
2. Full OIDF certification suite is **not** executed in CI; operators may run it
   externally against a deployed demo.

## Consequences

- Attack harness runs with `cargo test -p oauth --test attack_harness`.
- Fuzz smoke runs on nightly in CI; stable `parser_smoke` always runs with tests.
- Full OpenID Foundation certification remains out of scope; the checklist maps
  profiles to done/partial/open.

## Alternatives considered

- **Only external OIDF suite.** Rejected as the sole gate; needs network and
  operator setup. Tracked via checklist instead.
