//! C ABI for compact JWS/JWT verification (ADR 0004).

const std = @import("std");
const testing = std.testing;
const jwks_mod = @import("jwks.zig");
const Jwks = jwks_mod.Jwks;
const policy_mod = @import("policy.zig");
const verify_mod = @import("verify.zig");

pub const AUTHCRAFT_JOSE_OK: c_int = 0;
pub const AUTHCRAFT_JOSE_REJECTED: c_int = 1;
pub const AUTHCRAFT_JOSE_CONFIG: c_int = 2;
pub const AUTHCRAFT_JOSE_INVALID: c_int = 3;

pub const VerifyInput = extern struct {
    token: ?[*]const u8,
    token_len: usize,
    jwks: ?[*]const u8,
    jwks_len: usize,
    policy: ?[*]const u8,
    policy_len: usize,
};

pub const VerifyResult = extern struct {
    error_code: [32]u8,
    kid: [256]u8,
    alg: [16]u8,
};

fn clearResult(result: *VerifyResult) void {
    @memset(&result.error_code, 0);
    @memset(&result.kid, 0);
    @memset(&result.alg, 0);
}

fn setField(dest: []u8, src: []const u8) void {
    @memset(dest, 0);
    const n = @min(src.len, dest.len - 1);
    @memcpy(dest[0..n], src[0..n]);
}

fn sliceOrNull(ptr: ?[*]const u8, len: usize) ?[]const u8 {
    const p = ptr orelse return null;
    if (len == 0) return null;
    return p[0..len];
}

/// C entry point. See `include/authcraft_jose.h` and ADR 0004.
pub export fn authcraft_jose_verify(input: ?*const VerifyInput, result: ?*VerifyResult) callconv(.C) c_int {
    const out = result orelse return AUTHCRAFT_JOSE_INVALID;
    clearResult(out);
    const in = input orelse return AUTHCRAFT_JOSE_INVALID;

    const token = sliceOrNull(in.token, in.token_len) orelse {
        setField(&out.error_code, "config");
        return AUTHCRAFT_JOSE_INVALID;
    };
    const jwks_bytes = sliceOrNull(in.jwks, in.jwks_len) orelse {
        setField(&out.error_code, "config");
        return AUTHCRAFT_JOSE_INVALID;
    };
    const policy_bytes = sliceOrNull(in.policy, in.policy_len) orelse {
        setField(&out.error_code, "config");
        return AUTHCRAFT_JOSE_INVALID;
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var jwks = Jwks.parse(allocator, jwks_bytes) catch {
        setField(&out.error_code, "config");
        return AUTHCRAFT_JOSE_CONFIG;
    };
    defer jwks.deinit();

    var policy = policy_mod.parse(allocator, policy_bytes) catch {
        setField(&out.error_code, "config");
        return AUTHCRAFT_JOSE_CONFIG;
    };
    defer policy.deinit();

    if (verify_mod.verify(allocator, token, &jwks, &policy.policy)) |verified_const| {
        var verified = verified_const;
        defer verified.deinit(allocator);
        setField(&out.kid, verified.kid);
        setField(&out.alg, verified.alg.name());
        return AUTHCRAFT_JOSE_OK;
    } else |err| {
        setField(&out.error_code, verify_mod.errorCode(err));
        return AUTHCRAFT_JOSE_REJECTED;
    }
}

fn cstrField(buf: []const u8) []const u8 {
    return std.mem.sliceTo(buf, 0);
}

test "c abi accepts positive vector token" {
    const token =
        \\eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.eyJleHAiOjEwMX0.v6crgAoEo86g2X89VfNnnXvQ5xUvGG5uiGLceBYoAo8deIGLzAKtF7kG21o7EMrbSxgkVfy_LjIr-Wyr3-ScDQ
    ;
    const jwks =
        \\{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}]}
    ;
    const policy =
        \\{"algs":["EdDSA"],"now":100}
    ;

    var result: VerifyResult = undefined;
    const input = VerifyInput{
        .token = token.ptr,
        .token_len = token.len,
        .jwks = jwks.ptr,
        .jwks_len = jwks.len,
        .policy = policy.ptr,
        .policy_len = policy.len,
    };
    const rc = authcraft_jose_verify(&input, &result);
    try testing.expectEqual(AUTHCRAFT_JOSE_OK, rc);
    try testing.expectEqualStrings("k1", cstrField(&result.kid));
    try testing.expectEqualStrings("EdDSA", cstrField(&result.alg));
    try testing.expectEqualStrings("", cstrField(&result.error_code));
}

test "c abi rejects expired with adr code" {
    const token =
        \\eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.eyJleHAiOjEwMX0.v6crgAoEo86g2X89VfNnnXvQ5xUvGG5uiGLceBYoAo8deIGLzAKtF7kG21o7EMrbSxgkVfy_LjIr-Wyr3-ScDQ
    ;
    const jwks =
        \\{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}]}
    ;
    const policy =
        \\{"algs":["EdDSA"],"now":101}
    ;

    var result: VerifyResult = undefined;
    const input = VerifyInput{
        .token = token.ptr,
        .token_len = token.len,
        .jwks = jwks.ptr,
        .jwks_len = jwks.len,
        .policy = policy.ptr,
        .policy_len = policy.len,
    };
    const rc = authcraft_jose_verify(&input, &result);
    try testing.expectEqual(AUTHCRAFT_JOSE_REJECTED, rc);
    try testing.expectEqualStrings("expired", cstrField(&result.error_code));
}

test "c abi config error on bad jwks" {
    const token = "a.b.c";
    const jwks = "not-json";
    const policy = "{\"algs\":[\"EdDSA\"],\"now\":1}";
    var result: VerifyResult = undefined;
    const input = VerifyInput{
        .token = token.ptr,
        .token_len = token.len,
        .jwks = jwks.ptr,
        .jwks_len = jwks.len,
        .policy = policy.ptr,
        .policy_len = policy.len,
    };
    const rc = authcraft_jose_verify(&input, &result);
    try testing.expectEqual(AUTHCRAFT_JOSE_CONFIG, rc);
    try testing.expectEqualStrings("config", cstrField(&result.error_code));
}

test "c abi invalid on null input" {
    var result: VerifyResult = undefined;
    try testing.expectEqual(AUTHCRAFT_JOSE_INVALID, authcraft_jose_verify(null, &result));
    try testing.expectEqual(AUTHCRAFT_JOSE_INVALID, authcraft_jose_verify(&VerifyInput{
        .token = null,
        .token_len = 0,
        .jwks = null,
        .jwks_len = 0,
        .policy = null,
        .policy_len = 0,
    }, null));
}
