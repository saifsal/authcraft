//! Runs the shared test vectors under `testvectors/` against the Zig verifier
//! (ADR 0002). Every implementation must produce the verdict in `expect`.

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
const verify_mod = @import("verify.zig");
const Policy = verify_mod.Policy;

fn testvectorsRoot(allocator: Allocator) ![]u8 {
    // `zig build test` runs with cwd = the zig/ package directory.
    const candidates = [_][]const u8{
        "../testvectors",
        "testvectors",
        "../../testvectors",
    };
    for (candidates) |c| {
        var dir = std.fs.cwd().openDir(c, .{}) catch continue;
        dir.close();
        return try allocator.dupe(u8, c);
    }
    return error.TestVectorsNotFound;
}

fn writeJson(value: json.Value, writer: anytype) !void {
    switch (value) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .number => |n| switch (n) {
            .int => |i| try writer.print("{d}", .{i}),
            .other => |s| try writer.writeAll(s),
        },
        .string => |s| try writeJsonString(s, writer),
        .array => |items| {
            try writer.writeByte('[');
            for (items, 0..) |item, i| {
                if (i > 0) try writer.writeByte(',');
                try writeJson(item, writer);
            }
            try writer.writeByte(']');
        },
        .object => |members| {
            try writer.writeByte('{');
            for (members, 0..) |m, i| {
                if (i > 0) try writer.writeByte(',');
                try writeJsonString(m.name, writer);
                try writer.writeByte(':');
                try writeJson(m.value, writer);
            }
            try writer.writeByte('}');
        },
    }
}

fn writeJsonString(s: []const u8, writer: anytype) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn policyFrom(allocator: Allocator, value: json.Value, case_name: []const u8) !Policy {
    const algs_val = value.get("algs") orelse std.debug.panic("{s}: policy.algs missing", .{case_name});
    const algs_arr = algs_val.asArray() orelse std.debug.panic("{s}: policy.algs must be an array", .{case_name});
    var algs = try allocator.alloc(Alg, algs_arr.len);
    errdefer allocator.free(algs);
    for (algs_arr, 0..) |a, i| {
        const name = a.asStr() orelse std.debug.panic("{s}: alg must be a string", .{case_name});
        algs[i] = Alg.fromName(name) orelse std.debug.panic("{s}: unknown alg {s}", .{ case_name, name });
    }

    const now = (value.get("now") orelse std.debug.panic("{s}: now missing", .{case_name})).asI64() orelse
        std.debug.panic("{s}: now must be an integer", .{case_name});

    const leeway: u64 = if (value.get("leeway")) |v|
        @intCast(v.asI64() orelse std.debug.panic("{s}: leeway must be an integer", .{case_name}))
    else
        0;

    const max_token_bytes: usize = if (value.get("max_token_bytes")) |v|
        @intCast(v.asI64() orelse std.debug.panic("{s}: max_token_bytes must be an integer", .{case_name}))
    else
        8192;

    return .{
        .algorithms = algs,
        .issuer = if (value.get("iss")) |v| v.asStr() else null,
        .audience = if (value.get("aud")) |v| v.asStr() else null,
        .now = now,
        .leeway = leeway,
        .typ = if (value.get("typ")) |v| v.asStr() else null,
        .max_token_bytes = max_token_bytes,
    };
}

fn runVector(allocator: Allocator, path: []const u8) !void {
    const text = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    defer allocator.free(text);

    const root = try json.parse(allocator, text);
    defer root.deinit(allocator);

    const id = (root.get("id") orelse std.debug.panic("{s}: missing id", .{path})).asStr().?;
    try testing.expectEqualStrings(std.fs.path.stem(path), id);
    const source = (root.get("source") orelse std.debug.panic("{s}: missing source", .{path})).asStr().?;
    try testing.expect(source.len > 0);

    var jwks_buf: std.ArrayListUnmanaged(u8) = .{};
    defer jwks_buf.deinit(allocator);
    try writeJson((root.get("jwks") orelse std.debug.panic("{s}: missing jwks", .{path})).*, jwks_buf.writer(allocator));

    var jwks = Jwks.parse(allocator, jwks_buf.items) catch |err| {
        std.debug.panic("{s}: JWKS is a configuration error: {s}", .{ path, @errorName(err) });
    };
    defer jwks.deinit();

    var policy = try policyFrom(allocator, (root.get("policy") orelse std.debug.panic("{s}: missing policy", .{path})).*, path);
    defer allocator.free(@constCast(policy.algorithms));

    const token = (root.get("token") orelse std.debug.panic("{s}: missing token", .{path})).asStr().?;
    const expect = root.get("expect") orelse std.debug.panic("{s}: missing expect", .{path});
    const ok = switch ((expect.get("ok") orelse std.debug.panic("{s}: expect.ok missing", .{path})).*) {
        .bool => |b| b,
        else => std.debug.panic("{s}: expect.ok must be a boolean", .{path}),
    };

    if (verify_mod.verify(allocator, token, &jwks, &policy)) |verified_const| {
        var verified = verified_const;
        defer verified.deinit(allocator);
        if (!ok) {
            std.debug.panic("{s}: expected rejection, token verified", .{path});
        }
        if (expect.get("kid")) |kid_v| {
            try testing.expectEqualStrings(kid_v.asStr().?, verified.kid);
        }
        if (expect.get("alg")) |alg_v| {
            try testing.expectEqualStrings(alg_v.asStr().?, verified.alg.name());
        }
    } else |err| {
        if (ok) {
            std.debug.panic("{s}: expected success, got {s}", .{ path, verify_mod.errorCode(err) });
        }
        const expected = (expect.get("error") orelse std.debug.panic("{s}: expect.error missing", .{path})).asStr().?;
        try testing.expectEqualStrings(expected, verify_mod.errorCode(err));
    }
}

fn collectVectors(allocator: Allocator, root_dir: []const u8) ![][]u8 {
    var list: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (list.items) |p| allocator.free(p);
        list.deinit(allocator);
    }

    for ([_][]const u8{ "generated", "rfc" }) |sub| {
        const dir_path = try std.fs.path.join(allocator, &.{ root_dir, sub });
        defer allocator.free(dir_path);
        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch continue;
        defer dir.close();

        var names: std.ArrayListUnmanaged([]u8) = .{};
        defer {
            for (names.items) |n| allocator.free(n);
            names.deinit(allocator);
        }

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".json")) continue;
            try names.append(allocator, try allocator.dupe(u8, entry.name));
        }

        std.mem.sort([]u8, names.items, {}, struct {
            fn less(_: void, a: []u8, b: []u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.less);

        for (names.items) |name| {
            const full = try std.fs.path.join(allocator, &.{ dir_path, name });
            try list.append(allocator, full);
        }
    }

    return try list.toOwnedSlice(allocator);
}

test "shared vectors match the zig verifier" {
    const root = try testvectorsRoot(testing.allocator);
    defer testing.allocator.free(root);

    const files = try collectVectors(testing.allocator, root);
    defer {
        for (files) |f| testing.allocator.free(f);
        testing.allocator.free(files);
    }
    try testing.expect(files.len > 0);

    for (files) |path| {
        try runVector(testing.allocator, path);
    }
}

test "rfc signatures match when kid is absent" {
    const root = try testvectorsRoot(testing.allocator);
    defer testing.allocator.free(root);

    const cases = [_]struct { id: []const u8, algorithm: Alg }{
        .{ .id = "rfc7515-a1-hs256", .algorithm = .hs256 },
        .{ .id = "rfc7515-a3-es256", .algorithm = .es256 },
        .{ .id = "rfc8037-a4-eddsa", .algorithm = .eddsa },
    };

    for (cases) |case| {
        const name = try std.fmt.allocPrint(testing.allocator, "{s}.json", .{case.id});
        defer testing.allocator.free(name);
        const path = try std.fs.path.join(testing.allocator, &.{ root, "rfc", name });
        defer testing.allocator.free(path);

        const text = try std.fs.cwd().readFileAlloc(testing.allocator, path, 1024 * 1024);
        defer testing.allocator.free(text);
        const parsed = try json.parse(testing.allocator, text);
        defer parsed.deinit(testing.allocator);

        const expect_err = parsed.get("expect").?.get("error").?.asStr().?;
        try testing.expectEqualStrings("key_not_found", expect_err);

        var jwks_buf: std.ArrayListUnmanaged(u8) = .{};
        defer jwks_buf.deinit(testing.allocator);
        try writeJson(parsed.get("jwks").?.*, jwks_buf.writer(testing.allocator));
        var jwks = try Jwks.parse(testing.allocator, jwks_buf.items);
        defer jwks.deinit();

        const material = blk: {
            for (jwks.keys) |k| {
                if (k.material) |m| break :blk m;
            }
            std.debug.panic("{s}: no usable key", .{case.id});
        };

        const token = parsed.get("token").?.asStr().?;
        const dot = std.mem.lastIndexOfScalar(u8, token, '.') orelse
            std.debug.panic("{s}: no signature separator", .{case.id});
        const signing_input = token[0..dot];
        const signature_segment = token[dot + 1 ..];
        const signature_bytes = try b64url.decode(testing.allocator, signature_segment);
        defer testing.allocator.free(signature_bytes);
        try signature.verify(case.algorithm, material, signing_input, signature_bytes);
    }
}
