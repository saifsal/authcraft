//! Zig JOSE/JWT verifier for authcraft (M0).
//!
//! Mirrors the Rust `jose` crate against the shared vectors in
//! `testvectors/`. Implements compact JWS verification per ADR 0003.

pub const alg = @import("alg.zig");
pub const b64url = @import("b64url.zig");
pub const json = @import("json.zig");
pub const jwk = @import("jwk.zig");
pub const jwks = @import("jwks.zig");
pub const signature = @import("signature.zig");
pub const verify = @import("verify.zig");

test {
    _ = alg;
    _ = b64url;
    _ = json;
    _ = jwk;
    _ = jwks;
    _ = signature;
    _ = verify;
    _ = @import("vectors.zig");
}
