# ADR 0007: Zig edge-auth JWT verify sidecar

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

ADR 0004 exported `authcraft_jose_verify` so an edge process can accept or
reject Bearer JWTs without embedding Zig APIs. This decision scopes the first
sidecar that uses that ABI.

## Decision

1. **Verify-only HTTP service** under `zig/` (`src/sidecar.zig`), default bind
   `127.0.0.1:8091`. No reverse-proxy upstream forwarding in this slice.
2. **Routes:**
   - `GET /healthz` → `200`
   - `GET /verify` → requires `Authorization: Bearer <token>`; loads JWKS and
     policy from files (CLI `--jwks` / `--policy`); calls
     `authcraft_jose_verify`; on accept returns `200` with JSON
     `{"kid":"...","alg":"..."}` (and matching response headers); on reject
     returns `401` with JSON `{"error":"<ADR 0003 code>"}`.
3. **Configuration errors** (unreadable files, bad JWKS/policy) are process
   startup failures, not per-request 5xx from bad JWKS mid-flight: JWKS and
   policy are read once at start and held in memory.
4. **Same JSON shapes as `jose-cli verify`** for JWKS and policy (ADR 0004).
5. Shared verify wiring is unit-tested without binding a socket; `zig build test`
   covers it. `zig build sidecar` installs the binary.

## Consequences

- Edge demos can gate requests with the same verdicts as the shared vector suite.
- Adding upstream proxying or mTLS needs a later ADR or additive revision.
- The sidecar links the in-tree jose module; it does not call the Rust server.

## Alternatives considered

- **Call Zig `verify` without the C ABI.** Rejected for this slice; the point is
  to exercise the embedding boundary ADR 0004 defined.
- **Full reverse proxy.** Deferred; keep I/O boring until verify is proven.
