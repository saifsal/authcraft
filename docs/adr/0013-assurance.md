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

### B2 — fuzzing (pending)

### B3 — OpenID conformance checklist (pending)

## Consequences

- Attack harness runs with `cargo test -p oauth --test attack_harness`.
- Full OpenID Foundation certification remains out of scope; the checklist maps
  profiles to done/partial/open.

## Alternatives considered

- **Only external OIDF suite.** Rejected as the sole gate; needs network and
  operator setup. Tracked via checklist instead.
