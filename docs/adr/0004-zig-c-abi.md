# ADR 0004: Zig verifier C ABI

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

The Zig package verifies compact JWS/JWT values against the same contract as
Rust and Go (ADR 0002, ADR 0003). Later work wants a small edge-auth sidecar
that can be embedded from C or other languages without pulling in a Zig
runtime API. A stable C ABI is the boundary for that embedding. The sidecar
itself is not in this decision; only the verify entry point is.

## Decision

1. **One verify entry point.** `authcraft_jose_verify` takes a compact token,
   a JWKS document, and a policy document as byte buffers, plus an output
   struct. There is no signing, keygen, or network I/O in the ABI.
2. **Policy and JWKS are the same JSON shapes as `jose-cli verify`.** Callers
   that already drive the Rust CLI can reuse files byte-for-byte. Configuration
   errors (bad JWKS or policy) are distinct from token rejections.
3. **Return codes mirror the CLI exit codes:**
   - `0` — token accepted; `kid` and `alg` are filled in the result.
   - `1` — token rejected; `error` holds an ADR 0003 code.
   - `2` — configuration error (JWKS or policy); `error` is `config`.
   - `3` — invalid arguments (null pointers or empty required buffers).
4. **No heap ownership crosses the ABI.** The library allocates only for the
   duration of the call. Result strings are copied into fixed-size fields in
   the caller-provided result struct. Claims are not returned; edge use cases
   that need claims can parse the payload after a successful verify, or a
   later ABI can add an opt-in claims buffer.
5. **The shared library soname / install name is `authcraft_jose`.** The Zig
   package still builds the static `jose` library for in-tree tests. The public
   header is `include/authcraft_jose.h`.

## Consequences

- Embedding languages get a single, boring C function that cannot diverge from
  the vector suite without failing `zig build test`.
- Expanding the ABI (claims out-params, streaming) needs a new ADR or an
  additive revision of this one; changing return codes or error strings breaks
  callers.
- The edge-auth sidecar can link this library and treat HTTP concerns
  separately.

## Alternatives considered

- **Return claims as a JSON buffer.** Deferred. Most edge checks only need
  accept/reject plus `kid`/`alg` for logging.
- **Pass policy as individual C fields.** Rejected for M0/M1 adjacency: it
  would drift from `jose-cli` and the vector `policy` objects.
- **Expose Zig calling convention only.** Rejected; the point of this layer is
  language-neutral embedding.
