//! Bearer JWT verify wiring for the edge-auth sidecar (ADR 0007).
//! Calls `authcraft_jose_verify` (ADR 0004).
//!
//! Sender-constrained tokens (ADR 0007 amendment): the sidecar cannot check a
//! DPoP proof (RFC 9449) or a TLS client certificate (RFC 8705), so a token
//! that verifies but carries a `cnf` claim is refused with
//! `token_binding_unsupported` instead of being accepted as a bearer token.

const std = @import("std");
const testing = std.testing;
const c_api = @import("c_api.zig");
const b64url = @import("b64url.zig");
const json = @import("json.zig");

/// Sidecar-level rejection for bound tokens. Not an ADR 0003 verifier code.
pub const binding_unsupported = "token_binding_unsupported";

/// Whether the payload of an already-verified compact JWS has a `cnf` member.
/// Any decode or parse failure counts as bound, so the caller fails closed.
fn hasConfirmation(token: []const u8) bool {
    var it = std.mem.splitScalar(u8, token, '.');
    _ = it.next() orelse return true;
    const payload_b64 = it.next() orelse return true;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const payload = b64url.decode(allocator, payload_b64) catch return true;
    const claims = json.parse(allocator, payload) catch return true;
    return claims.get("cnf") != null;
}

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
        c_api.AUTHCRAFT_JOSE_OK => if (hasConfirmation(token)) .{
            .status = 401,
            .error_code = binding_unsupported,
            .kid = "",
            .alg = "",
        } else .{
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

test "verifyBearer refuses DPoP- and certificate-bound tokens" {
    const jwks =
        \\{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}]}
    ;
    const policy =
        \\{"algs":["EdDSA"],"now":100}
    ;
    // {"exp":101,"cnf":{"jkt":...}} and {"exp":101,"cnf":{"x5t#S256":...}},
    // signed with the RFC 8037 A.1 key.
    const tokens = [_][]const u8{
        "eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.eyJleHAiOjEwMSwiY25mIjp7ImprdCI6IjBaY09DT1JaTll5LURXcHFxMzBqWnlKR0hUTjBkMkhnbEJWM3VpZ3VBNEkifX0.jqbv_rRVDGN0d91bYbc44641-Uk5gVw4q_9mGgArFbiKTu3epfOOQJ_1OHn1eo-IUpu674sQFXHFH5H0uzuPDQ",
        "eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.eyJleHAiOjEwMSwiY25mIjp7Ing1dCNTMjU2IjoiYndjSzBlc2MzQUNDM0RCMlk1X2xFU3NYRThvOWx0YzA1Tzg5amROLWRnMiJ9fQ.voEFlMpfNVfePsjFTeHZlLZqUAoGDDfLN3R7gYx-9-HTFaPe_SIKFozoNp5osUmnklCjsy_L5K57fZ3GOqqaCA",
    };
    for (tokens) |token| {
        var result: c_api.VerifyResult = undefined;
        const out = verifyBearer(token, jwks, policy, &result);
        try testing.expectEqual(@as(u16, 401), out.status);
        try testing.expectEqualStrings(binding_unsupported, out.error_code);
    }
}

test "hasConfirmation fails closed on undecodable payload" {
    try testing.expect(hasConfirmation("only-one-segment"));
    try testing.expect(hasConfirmation("a.!!!.c"));
    try testing.expect(!hasConfirmation("e30.eyJleHAiOjF9.c"));
}
