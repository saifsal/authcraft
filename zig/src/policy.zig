//! Policy JSON matching `jose-cli verify` / shared vector `policy` objects.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const alg_mod = @import("alg.zig");
const Alg = alg_mod.Alg;
const json = @import("json.zig");
const verify_mod = @import("verify.zig");
const Policy = verify_mod.Policy;

pub const PolicyError = error{
    NotObject,
    MissingAlgs,
    AlgsNotArray,
    AlgNotString,
    UnknownAlg,
    MissingNow,
    NowNotInt,
    LeewayNotInt,
    LeewayNegative,
    MaxTokenBytesNotInt,
    MaxTokenBytesNegative,
    IssNotString,
    AudNotString,
    TypNotString,
    OutOfMemory,
};

/// Owned policy backing storage for string/alg slices.
pub const PolicyOwned = struct {
    policy: Policy,
    algorithms: []Alg,
    issuer: ?[]u8 = null,
    audience: ?[]u8 = null,
    typ: ?[]u8 = null,
    allocator: Allocator,

    pub fn deinit(self: *PolicyOwned) void {
        self.allocator.free(self.algorithms);
        if (self.issuer) |s| self.allocator.free(s);
        if (self.audience) |s| self.allocator.free(s);
        if (self.typ) |s| self.allocator.free(s);
        self.* = undefined;
    }
};

/// Parses a policy JSON document into an owned `Policy`.
pub fn parse(allocator: Allocator, input: []const u8) PolicyError!PolicyOwned {
    const root = json.parse(allocator, input) catch return error.NotObject;
    defer root.deinit(allocator);
    if (root.asObject() == null) return error.NotObject;

    const algs_val = root.get("algs") orelse return error.MissingAlgs;
    const algs_arr = algs_val.asArray() orelse return error.AlgsNotArray;
    var algorithms = try allocator.alloc(Alg, algs_arr.len);
    errdefer allocator.free(algorithms);
    for (algs_arr, 0..) |a, i| {
        const name = a.asStr() orelse return error.AlgNotString;
        algorithms[i] = Alg.fromName(name) orelse return error.UnknownAlg;
    }

    const now_val = root.get("now") orelse return error.MissingNow;
    const now = now_val.asI64() orelse return error.NowNotInt;

    const leeway: u64 = if (root.get("leeway")) |v| blk: {
        const n = v.asI64() orelse return error.LeewayNotInt;
        if (n < 0) return error.LeewayNegative;
        break :blk @intCast(n);
    } else 0;

    const max_token_bytes: usize = if (root.get("max_token_bytes")) |v| blk: {
        const n = v.asI64() orelse return error.MaxTokenBytesNotInt;
        if (n < 0) return error.MaxTokenBytesNegative;
        break :blk @intCast(n);
    } else 8192;

    const issuer = try optionalOwnedString(allocator, root, "iss", error.IssNotString);
    errdefer if (issuer) |s| allocator.free(s);
    const audience = try optionalOwnedString(allocator, root, "aud", error.AudNotString);
    errdefer if (audience) |s| allocator.free(s);
    const typ = try optionalOwnedString(allocator, root, "typ", error.TypNotString);
    errdefer if (typ) |s| allocator.free(s);

    return .{
        .policy = .{
            .algorithms = algorithms,
            .issuer = issuer,
            .audience = audience,
            .now = now,
            .leeway = leeway,
            .typ = typ,
            .max_token_bytes = max_token_bytes,
        },
        .algorithms = algorithms,
        .issuer = issuer,
        .audience = audience,
        .typ = typ,
        .allocator = allocator,
    };
}

fn optionalOwnedString(
    allocator: Allocator,
    root: json.Value,
    name: []const u8,
    not_string: PolicyError,
) PolicyError!?[]u8 {
    const v = root.get(name) orelse return null;
    const s = v.asStr() orelse return not_string;
    return try allocator.dupe(u8, s);
}

test "parses minimal policy" {
    var owned = try parse(testing.allocator, "{\"algs\":[\"EdDSA\"],\"now\":100}");
    defer owned.deinit();
    try testing.expectEqual(@as(usize, 1), owned.policy.algorithms.len);
    try testing.expect(owned.policy.algorithms[0] == .eddsa);
    try testing.expectEqual(@as(i64, 100), owned.policy.now);
    try testing.expectEqual(@as(usize, 8192), owned.policy.max_token_bytes);
}

test "rejects unknown alg" {
    try testing.expectError(error.UnknownAlg, parse(testing.allocator, "{\"algs\":[\"none\"],\"now\":1}"));
}
