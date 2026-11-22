//! Compact JWS verification and JWT claim validation following ADR 0003.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const alg_mod = @import("alg.zig");
const Alg = alg_mod.Alg;
const b64url = @import("b64url.zig");
const json = @import("json.zig");
const jwks_mod = @import("jwks.zig");
const Jwks = jwks_mod.Jwks;
const signature = @import("signature.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Policy = struct {
    algorithms: []const Alg,
    issuer: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    now: i64,
    leeway: u64 = 0,
    typ: ?[]const u8 = null,
    max_token_bytes: usize = 8192,
};

pub const VerifyError = error{
    TooLarge,
    Malformed,
    CritUnsupported,
    AlgNotAllowed,
    TypMismatch,
    KeyNotFound,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    Expired,
    NotYetValid,
    OutOfMemory,
};

pub fn errorCode(err: VerifyError) []const u8 {
    return switch (err) {
        error.TooLarge => "too_large",
        error.Malformed => "malformed",
        error.CritUnsupported => "crit_unsupported",
        error.AlgNotAllowed => "alg_not_allowed",
        error.TypMismatch => "typ_mismatch",
        error.KeyNotFound => "key_not_found",
        error.BadSignature => "bad_signature",
        error.WrongIssuer => "wrong_issuer",
        error.WrongAudience => "wrong_audience",
        error.Expired => "expired",
        error.NotYetValid => "not_yet_valid",
        error.OutOfMemory => "malformed", // not in ADR taxonomy; should not escape tests
    };
}

pub const VerifiedToken = struct {
    kid: []u8,
    alg: Alg,
    claims: json.Value,

    pub fn deinit(self: *VerifiedToken, allocator: Allocator) void {
        allocator.free(self.kid);
        self.claims.deinit(allocator);
        self.* = undefined;
    }
};

/// Verifies one compact JWS and validates its JWT claims according to ADR 0003.
pub fn verify(allocator: Allocator, token: []const u8, jwks: *const Jwks, policy: *const Policy) VerifyError!VerifiedToken {
    if (token.len > policy.max_token_bytes) return error.TooLarge;

    // Token text must be ASCII base64url + dots; reject non-UTF-8 early.
    if (!std.unicode.utf8ValidateSlice(token)) return error.Malformed;

    var parts = std.mem.splitScalar(u8, token, '.');
    const header_segment = parts.next() orelse return error.Malformed;
    const payload_segment = parts.next() orelse return error.Malformed;
    const signature_segment = parts.next() orelse return error.Malformed;
    if (parts.next() != null or
        header_segment.len == 0 or
        payload_segment.len == 0 or
        signature_segment.len == 0 or
        !isBase64urlAlphabet(header_segment) or
        !isBase64urlAlphabet(payload_segment) or
        !isBase64urlAlphabet(signature_segment))
    {
        return error.Malformed;
    }

    const header_bytes = b64url.decode(allocator, header_segment) catch return error.Malformed;
    defer allocator.free(header_bytes);
    const header = json.parse(allocator, header_bytes) catch return error.Malformed;
    defer header.deinit(allocator);
    if (header.asObject() == null) return error.Malformed;

    if (header.get("crit")) |crit| {
        const entries = crit.asArray() orelse return error.Malformed;
        if (entries.len == 0) return error.Malformed;
        for (entries) |entry| {
            if (entry.asStr() == null) return error.Malformed;
        }
        return error.CritUnsupported;
    }

    const alg_name = (header.get("alg") orelse return error.AlgNotAllowed).asStr() orelse return error.AlgNotAllowed;
    const algorithm = Alg.fromName(alg_name) orelse return error.AlgNotAllowed;
    if (!algAllowed(policy.algorithms, algorithm)) return error.AlgNotAllowed;

    if (policy.typ) |expected_typ| {
        const actual_typ = (header.get("typ") orelse return error.TypMismatch).asStr() orelse return error.TypMismatch;
        if (!typMatches(actual_typ, expected_typ)) return error.TypMismatch;
    }

    const kid = (header.get("kid") orelse return error.KeyNotFound).asStr() orelse return error.KeyNotFound;
    const key = jwks.find(kid, algorithm) orelse return error.KeyNotFound;

    const signature_bytes = b64url.decode(allocator, signature_segment) catch return error.BadSignature;
    defer allocator.free(signature_bytes);
    const expected_len: usize = switch (algorithm) {
        .eddsa, .es256 => 64,
        .hs256 => 32,
    };
    if (signature_bytes.len != expected_len) return error.BadSignature;

    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_segment, payload_segment });
    defer allocator.free(signing_input);

    const material = key.material orelse return error.KeyNotFound;
    signature.verify(algorithm, material, signing_input, signature_bytes) catch return error.BadSignature;

    const payload_bytes = b64url.decode(allocator, payload_segment) catch return error.Malformed;
    defer allocator.free(payload_bytes);
    const claims = json.parse(allocator, payload_bytes) catch return error.Malformed;
    errdefer claims.deinit(allocator);
    if (claims.asObject() == null) return error.Malformed;
    try validateClaims(claims, policy);

    const kid_owned = try allocator.dupe(u8, kid);
    return .{
        .kid = kid_owned,
        .alg = algorithm,
        .claims = claims,
    };
}

fn algAllowed(algs: []const Alg, want: Alg) bool {
    for (algs) |a| {
        if (a == want) return true;
    }
    return false;
}

fn isBase64urlAlphabet(segment: []const u8) bool {
    for (segment) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_';
        if (!ok) return false;
    }
    return true;
}

fn typMatches(actual: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(normalizeTyp(actual), normalizeTyp(expected));
}

fn normalizeTyp(value: []const u8) []const u8 {
    if (value.len >= 12 and std.ascii.eqlIgnoreCase(value[0..12], "application/")) {
        return value[12..];
    }
    return value;
}

fn validateClaims(claims: json.Value, policy: *const Policy) VerifyError!void {
    if (policy.issuer) |expected| {
        const iss = claims.get("iss") orelse return error.WrongIssuer;
        const s = iss.asStr() orelse return error.WrongIssuer;
        if (!std.mem.eql(u8, s, expected)) return error.WrongIssuer;
    }

    if (policy.audience) |expected| {
        const audience = claims.get("aud") orelse return error.WrongAudience;
        const matches = switch (audience.*) {
            .string => |value| std.mem.eql(u8, value, expected),
            .array => |values| blk: {
                var found = false;
                for (values) |value| {
                    const s = value.asStr() orelse return error.Malformed;
                    if (std.mem.eql(u8, s, expected)) found = true;
                }
                break :blk found;
            },
            else => false,
        };
        if (!matches) return error.WrongAudience;
    }

    const exp = (claims.get("exp") orelse return error.Malformed).asI64() orelse return error.Malformed;
    const nbf: ?i64 = blk: {
        const v = claims.get("nbf") orelse break :blk null;
        break :blk v.asI64() orelse return error.Malformed;
    };

    const now: i128 = policy.now;
    const leeway: i128 = policy.leeway;
    if (now >= @as(i128, exp) + leeway) return error.Expired;
    if (nbf) |n| {
        if (now + leeway < @as(i128, n)) return error.NotYetValid;
    }
}

fn signedToken(allocator: Allocator, header: []const u8, payload: []const u8) ![]u8 {
    const header_b64 = try b64url.encode(allocator, header);
    defer allocator.free(header_b64);
    const payload_b64 = try b64url.encode(allocator, payload);
    defer allocator.free(payload_b64);
    const input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(input);
    const secret = [_]u8{0x42} ** alg_mod.hs256_min_key_len;
    var sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&sig, input, &secret);
    const sig_b64 = try b64url.encode(allocator, &sig);
    defer allocator.free(sig_b64);
    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ input, sig_b64 });
}

fn testJwks(allocator: Allocator) !Jwks {
    const secret = try b64url.encode(allocator, &[_]u8{0x42} ** alg_mod.hs256_min_key_len);
    defer allocator.free(secret);
    const doc = try std.fmt.allocPrint(
        allocator,
        "{{\"keys\":[{{\"kty\":\"oct\",\"kid\":\"h\",\"k\":\"{s}\"}}]}}",
        .{secret},
    );
    defer allocator.free(doc);
    return Jwks.parse(allocator, doc);
}

fn testPolicy() Policy {
    return .{
        .algorithms = &[_]Alg{.hs256},
        .issuer = "https://issuer.example",
        .audience = "api",
        .now = 100,
        .leeway = 0,
        .typ = "at+jwt",
        .max_token_bytes = 8192,
    };
}

test "verifies compact token and claims" {
    const header = "{\"alg\":\"HS256\",\"kid\":\"h\",\"typ\":\"application/at+jwt\"}";
    const payload = "{\"iss\":\"https://issuer.example\",\"aud\":[\"other\",\"api\"],\"exp\":101,\"nbf\":100}";
    const token = try signedToken(testing.allocator, header, payload);
    defer testing.allocator.free(token);
    var keys = try testJwks(testing.allocator);
    defer keys.deinit();
    const policy = testPolicy();
    var verified = try verify(testing.allocator, token, &keys, &policy);
    defer verified.deinit(testing.allocator);
    try testing.expectEqualStrings("h", verified.kid);
    try testing.expect(verified.alg == .hs256);
}

test "applies size shape algorithm and critical header checks" {
    var keys = try testJwks(testing.allocator);
    defer keys.deinit();
    var limited = testPolicy();
    limited.max_token_bytes = 2;
    try testing.expectError(error.TooLarge, verify(testing.allocator, "abc", &keys, &limited));
    const policy = testPolicy();
    try testing.expectError(error.Malformed, verify(testing.allocator, "a.b.c.d", &keys, &policy));

    const none_token = try signedToken(testing.allocator, "{\"alg\":\"none\",\"kid\":\"h\"}", "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":101}");
    defer testing.allocator.free(none_token);
    try testing.expectError(error.AlgNotAllowed, verify(testing.allocator, none_token, &keys, &policy));

    const crit_token = try signedToken(testing.allocator, "{\"alg\":\"HS256\",\"kid\":\"h\",\"crit\":[\"exp\"]}", "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":101}");
    defer testing.allocator.free(crit_token);
    try testing.expectError(error.CritUnsupported, verify(testing.allocator, crit_token, &keys, &policy));
}

test "verifies signature before parsing payload" {
    const token = try signedToken(testing.allocator, "{\"alg\":\"HS256\",\"kid\":\"h\",\"typ\":\"application/at+jwt\"}", "not-json");
    defer testing.allocator.free(token);
    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next().?;
    _ = it.next().?;
    const s = it.next().?;
    const bad_payload = try b64url.encode(testing.allocator, "still-not-json");
    defer testing.allocator.free(bad_payload);
    const altered = try std.fmt.allocPrint(testing.allocator, "{s}.{s}.{s}", .{ h, bad_payload, s });
    defer testing.allocator.free(altered);
    var keys = try testJwks(testing.allocator);
    defer keys.deinit();
    const policy = testPolicy();
    try testing.expectError(error.BadSignature, verify(testing.allocator, altered, &keys, &policy));
}
