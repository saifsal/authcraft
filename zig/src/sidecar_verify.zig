//! Bearer JWT verify wiring for the edge-auth sidecar (ADR 0007).
//! Calls `authcraft_jose_verify` (ADR 0004).

const std = @import("std");
const testing = std.testing;
const c_api = @import("c_api.zig");

pub const VerifyOutcome = struct {
    status: u16,
    /// ADR 0003 code on failure, or empty on success.
    error_code: []const u8,
    kid: []const u8,
    alg: []const u8,
};

pub fn extractBearer(authorization: ?[]const u8) ?[]const u8 {
    const header = authorization orelse return null;
    const prefix = "Bearer ";
    if (header.len <= prefix.len) return null;
    if (!std.mem.startsWith(u8, header, prefix)) return null;
    const token = header[prefix.len..];
    if (token.len == 0) return null;
    return token;
}

/// Verifies `token` against in-memory JWKS and policy via the C ABI.
pub fn verifyBearer(
    token: []const u8,
    jwks: []const u8,
    policy: []const u8,
    result_buf: *c_api.VerifyResult,
) VerifyOutcome {
    const input = c_api.VerifyInput{
        .token = token.ptr,
        .token_len = token.len,
        .jwks = jwks.ptr,
        .jwks_len = jwks.len,
        .policy = policy.ptr,
        .policy_len = policy.len,
    };
    const rc = c_api.authcraft_jose_verify(&input, result_buf);
    const err = std.mem.sliceTo(&result_buf.error_code, 0);
    const kid = std.mem.sliceTo(&result_buf.kid, 0);
    const alg = std.mem.sliceTo(&result_buf.alg, 0);
    return switch (rc) {
        c_api.AUTHCRAFT_JOSE_OK => .{
            .status = 200,
            .error_code = "",
            .kid = kid,
            .alg = alg,
        },
        c_api.AUTHCRAFT_JOSE_REJECTED => .{
            .status = 401,
            .error_code = err,
            .kid = "",
            .alg = "",
        },
        else => .{
            .status = 401,
            .error_code = if (err.len != 0) err else "config",
            .kid = "",
            .alg = "",
        },
    };
}

test "extractBearer requires Bearer scheme" {
    try testing.expect(extractBearer(null) == null);
    try testing.expect(extractBearer("Basic x") == null);
    try testing.expect(extractBearer("Bearer ") == null);
    try testing.expectEqualStrings("abc.def.ghi", extractBearer("Bearer abc.def.ghi").?);
}

test "verifyBearer accepts positive token via C ABI" {
    const token =
        \\eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.eyJleHAiOjEwMX0.v6crgAoEo86g2X89VfNnnXvQ5xUvGG5uiGLceBYoAo8deIGLzAKtF7kG21o7EMrbSxgkVfy_LjIr-Wyr3-ScDQ
    ;
    const jwks =
        \\{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}]}
    ;
    const policy =
        \\{"algs":["EdDSA"],"now":100}
    ;
    var result: c_api.VerifyResult = undefined;
    const out = verifyBearer(token, jwks, policy, &result);
    try testing.expectEqual(@as(u16, 200), out.status);
    try testing.expectEqualStrings("k1", out.kid);
    try testing.expectEqualStrings("EdDSA", out.alg);
}

test "verifyBearer rejects expired via C ABI" {
    const token =
        \\eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.eyJleHAiOjEwMX0.v6crgAoEo86g2X89VfNnnXvQ5xUvGG5uiGLceBYoAo8deIGLzAKtF7kG21o7EMrbSxgkVfy_LjIr-Wyr3-ScDQ
    ;
    const jwks =
        \\{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}]}
    ;
    const policy =
        \\{"algs":["EdDSA"],"now":101}
    ;
    var result: c_api.VerifyResult = undefined;
    const out = verifyBearer(token, jwks, policy, &result);
    try testing.expectEqual(@as(u16, 401), out.status);
    try testing.expectEqualStrings("expired", out.error_code);
}
