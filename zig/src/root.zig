//! Zig JOSE/JWT verifier for authcraft (M0).
//!
//! Mirrors the Rust `jose` crate against the shared vectors in
//! `testvectors/`. Implements compact JWS verification per ADR 0003.
//! The C ABI is documented in ADR 0004 (`include/authcraft_jose.h`).

pub const alg = @import("alg.zig");
pub const b64url = @import("b64url.zig");
pub const json = @import("json.zig");
pub const jwk = @import("jwk.zig");
pub const jwks = @import("jwks.zig");
pub const policy = @import("policy.zig");
pub const signature = @import("signature.zig");
pub const verify = @import("verify.zig");
pub const c_api = @import("c_api.zig");

test {
    _ = alg;
    _ = b64url;
    _ = json;
    _ = jwk;
    _ = jwks;
    _ = policy;
    _ = signature;
    _ = verify;
    _ = c_api;
    _ = @import("vectors.zig");
}
