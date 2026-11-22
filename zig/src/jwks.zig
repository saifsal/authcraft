//! JWKS parsing and the key lookup rules of ADR 0003, step 8.
//!
//! A `Jwks` is built from configuration, never from the network. Structurally
//! wrong documents fail `parse`; unusable key contents stay in the set but
//! can never be selected (`key_not_found`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const alg_mod = @import("alg.zig");
const Alg = alg_mod.Alg;
const b64url = @import("b64url.zig");
const json = @import("json.zig");
const jwk = @import("jwk.zig");
const PublicKey = jwk.PublicKey;

/// Key bytes a verifier can use.
pub const KeyMaterial = union(enum) {
    public: PublicKey,
    /// The shared secret of an `oct` key. Only `HS256` uses it.
    secret: []u8,

    pub fn deinit(self: KeyMaterial, allocator: Allocator) void {
        switch (self) {
            .public => {},
            .secret => |s| allocator.free(s),
        }
    }

    fn naturalAlg(self: KeyMaterial) Alg {
        return switch (self) {
            .public => |pk| switch (pk) {
                .ed25519 => .eddsa,
                .p256 => .es256,
            },
            .secret => .hs256,
        };
    }
};

/// One entry of a JWKS.
pub const Key = struct {
    kid: ?[]u8 = null,
    alg: ?[]u8 = null,
    use: ?[]u8 = null,
    /// `null` when the entry could not be turned into usable key bytes.
    material: ?KeyMaterial = null,

    pub fn deinit(self: Key, allocator: Allocator) void {
        if (self.kid) |k| allocator.free(k);
        if (self.alg) |a| allocator.free(a);
        if (self.use) |u| allocator.free(u);
        if (self.material) |m| m.deinit(allocator);
    }

    /// Whether this key may verify a token whose header says `alg`.
    fn usableFor(self: Key, want: Alg) bool {
        const material = self.material orelse return false;
        if (material.naturalAlg() != want) return false;
        if (self.alg) |declared| {
            if (!std.mem.eql(u8, declared, want.name())) return false;
        }
        if (self.use) |usage| {
            if (!std.mem.eql(u8, usage, "sig")) return false;
        }
        return true;
    }
};

pub const JwksError = error{
    Json,
    NotAnObject,
    MissingKeys,
    KeysNotArray,
    KeyNotObject,
    KidNotString,
    DuplicateKid,
    OutOfMemory,
};

/// A set of verification keys, looked up by `kid`.
pub const Jwks = struct {
    keys: []Key,
    allocator: Allocator,

    pub fn deinit(self: *Jwks) void {
        for (self.keys) |k| k.deinit(self.allocator);
        self.allocator.free(self.keys);
        self.* = undefined;
    }

    /// Parses a JWKS document.
    pub fn parse(allocator: Allocator, input: []const u8) JwksError!Jwks {
        const root = json.parse(allocator, input) catch return error.Json;
        defer root.deinit(allocator);

        if (root.asObject() == null) return error.NotAnObject;
        const keys_val = root.get("keys") orelse return error.MissingKeys;
        const entries = keys_val.asArray() orelse return error.KeysNotArray;

        var list: std.ArrayListUnmanaged(Key) = .{};
        errdefer {
            for (list.items) |k| k.deinit(allocator);
            list.deinit(allocator);
        }

        var seen = std.StringHashMap(void).init(allocator);
        defer seen.deinit();

        for (entries) |entry| {
            if (entry.asObject() == null) return error.KeyNotObject;

            const kid: ?[]u8 = blk: {
                const v = entry.get("kid") orelse break :blk null;
                const s = v.asStr() orelse return error.KidNotString;
                break :blk try allocator.dupe(u8, s);
            };

            if (kid) |k| {
                const gop = seen.getOrPut(k) catch {
                    allocator.free(k);
                    return error.OutOfMemory;
                };
                if (gop.found_existing) {
                    allocator.free(k);
                    return error.DuplicateKid;
                }
            }

            const key = keyFromJson(allocator, kid, entry) catch |err| {
                if (kid) |k| allocator.free(k);
                return err;
            };
            try list.append(allocator, key);
        }

        return .{ .keys = try list.toOwnedSlice(allocator), .allocator = allocator };
    }

    /// The key a token with this `kid` and `alg` must be verified with.
    pub fn find(self: *const Jwks, kid: []const u8, want: Alg) ?*const Key {
        for (self.keys) |*k| {
            const k_kid = k.kid orelse continue;
            if (!std.mem.eql(u8, k_kid, kid)) continue;
            if (k.usableFor(want)) return k;
            return null;
        }
        return null;
    }

    pub fn len(self: *const Jwks) usize {
        return self.keys.len;
    }

    pub fn isEmpty(self: *const Jwks) bool {
        return self.keys.len == 0;
    }
};

/// How a JSON string member was read for `alg` / `use`.
const MemberStr = union(enum) {
    absent,
    value: []u8,
    /// Present but not a string — makes the key unusable.
    invalid,
};

fn readOptionalString(allocator: Allocator, entry: json.Value, name: []const u8) JwksError!MemberStr {
    const v = entry.get(name) orelse return .absent;
    const s = v.asStr() orelse return .invalid;
    return .{ .value = try allocator.dupe(u8, s) };
}

fn keyFromJson(allocator: Allocator, kid: ?[]u8, entry: json.Value) JwksError!Key {
    // kid ownership transfers into Key on success; on failure caller frees kid.
    const alg_m = try readOptionalString(allocator, entry, "alg");
    errdefer switch (alg_m) {
        .value => |s| allocator.free(s),
        else => {},
    };
    const use_m = try readOptionalString(allocator, entry, "use");
    errdefer switch (use_m) {
        .value => |s| allocator.free(s),
        else => {},
    };

    const usable_meta = alg_m != .invalid and use_m != .invalid;
    const material: ?KeyMaterial = if (usable_meta) loadMaterial(allocator, entry) else null;

    return .{
        .kid = kid,
        .alg = switch (alg_m) {
            .value => |s| s,
            else => null,
        },
        .use = switch (use_m) {
            .value => |s| s,
            else => null,
        },
        .material = material,
    };
}

fn memberStr(entry: json.Value, name: []const u8) ?[]const u8 {
    const v = entry.get(name) orelse return null;
    return v.asStr();
}

fn memberBytes(allocator: Allocator, entry: json.Value, name: []const u8) ?[]u8 {
    const s = memberStr(entry, name) orelse return null;
    return b64url.decode(allocator, s) catch null;
}

fn loadMaterial(allocator: Allocator, entry: json.Value) ?KeyMaterial {
    const kty = memberStr(entry, "kty") orelse return null;
    if (std.mem.eql(u8, kty, "OKP")) {
        const crv = memberStr(entry, "crv") orelse return null;
        if (!std.mem.eql(u8, crv, "Ed25519")) return null;
        const x = memberBytes(allocator, entry, "x") orelse return null;
        defer allocator.free(x);
        const pk = PublicKey.ed25519FromBytes(x) catch return null;
        return .{ .public = pk };
    } else if (std.mem.eql(u8, kty, "EC")) {
        const crv = memberStr(entry, "crv") orelse return null;
        if (!std.mem.eql(u8, crv, "P-256")) return null;
        const x = memberBytes(allocator, entry, "x") orelse return null;
        defer allocator.free(x);
        const y = memberBytes(allocator, entry, "y") orelse return null;
        defer allocator.free(y);
        const pk = PublicKey.p256FromCoordinates(x, y) catch return null;
        return .{ .public = pk };
    } else if (std.mem.eql(u8, kty, "oct")) {
        const k = memberBytes(allocator, entry, "k") orelse return null;
        if (k.len < alg_mod.hs256_min_key_len) {
            allocator.free(k);
            return null;
        }
        return .{ .secret = k };
    } else {
        return null;
    }
}

const ed_x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const p_x = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
const p_y = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";

test "parses all three key types" {
    const secret = try b64url.encode(testing.allocator, &[_]u8{0x42} ** 32);
    defer testing.allocator.free(secret);
    const doc = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{s}\",\"kid\":\"e\"}},{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{s}\",\"y\":\"{s}\",\"kid\":\"p\"}},{{\"kty\":\"oct\",\"k\":\"{s}\",\"kid\":\"h\"}}]}}",
        .{ ed_x, p_x, p_y, secret },
    );
    defer testing.allocator.free(doc);
    var jwks = try Jwks.parse(testing.allocator, doc);
    defer jwks.deinit();
    try testing.expectEqual(@as(usize, 3), jwks.len());
    try testing.expect(jwks.find("e", .eddsa) != null);
    try testing.expect(jwks.find("p", .es256) != null);
    try testing.expect(jwks.find("h", .hs256) != null);
}

test "kid must match exactly" {
    const doc = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{s}\",\"kid\":\"Key-1\"}}]}}",
        .{ed_x},
    );
    defer testing.allocator.free(doc);
    var jwks = try Jwks.parse(testing.allocator, doc);
    defer jwks.deinit();
    try testing.expect(jwks.find("Key-1", .eddsa) != null);
    for ([_][]const u8{ "key-1", "Key-1 ", " Key-1", "Key-", "Key-12", "" }) |wrong| {
        try testing.expect(jwks.find(wrong, .eddsa) == null);
    }
}

test "duplicate kid is a configuration error" {
    const doc = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{s}\",\"kid\":\"k\"}},{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{s}\",\"kid\":\"k\"}}]}}",
        .{ ed_x, ed_x },
    );
    defer testing.allocator.free(doc);
    try testing.expectError(error.DuplicateKid, Jwks.parse(testing.allocator, doc));
}

test "use member must be sig" {
    const doc = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{s}\",\"kid\":\"sig\",\"use\":\"sig\"}},{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{s}\",\"kid\":\"enc\",\"use\":\"enc\"}},{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{s}\",\"kid\":\"none\"}}]}}",
        .{ ed_x, ed_x, ed_x },
    );
    defer testing.allocator.free(doc);
    var jwks = try Jwks.parse(testing.allocator, doc);
    defer jwks.deinit();
    try testing.expect(jwks.find("sig", .eddsa) != null);
    try testing.expect(jwks.find("none", .eddsa) != null);
    try testing.expect(jwks.find("enc", .eddsa) == null);
}

test "unusable keys stay without failing parse" {
    const doc =
        \\{"keys":[{"kid":"rsa","kty":"RSA","n":"AQAB","e":"AQAB"},{"kid":"short","kty":"OKP","crv":"Ed25519","x":"AAAA"}]}
    ;
    var jwks = try Jwks.parse(testing.allocator, doc);
    defer jwks.deinit();
    try testing.expectEqual(@as(usize, 2), jwks.len());
    try testing.expect(jwks.find("rsa", .eddsa) == null);
    try testing.expect(jwks.find("short", .eddsa) == null);
}
