//! Public keys and JWK thumbprints (RFC 7638).
//!
//! Only Ed25519 (`OKP`, RFC 8037) and P-256 (`EC`, RFC 7518 section 6.2) are modelled.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const b64url = @import("b64url.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ed25519_len: usize = 32;
pub const p256_coord_len: usize = 32;
/// SEC 1 uncompressed point format: `0x04 || X || Y`.
pub const p256_uncompressed_len: usize = 1 + 2 * p256_coord_len;

pub const KeyError = error{
    BadLength,
    NotUncompressedPoint,
    OutOfMemory,
};

/// A public verification key.
///
/// Construction checks lengths only. It does not check that a P-256 point is
/// on the curve. The signature verifier rejects invalid points when it is used.
pub const PublicKey = union(enum) {
    ed25519: [ed25519_len]u8,
    p256: struct {
        x: [p256_coord_len]u8,
        y: [p256_coord_len]u8,
    },

    pub fn ed25519FromBytes(bytes: []const u8) KeyError!PublicKey {
        if (bytes.len != ed25519_len) return error.BadLength;
        var x: [ed25519_len]u8 = undefined;
        @memcpy(&x, bytes);
        return .{ .ed25519 = x };
    }

    pub fn p256FromCoordinates(x: []const u8, y: []const u8) KeyError!PublicKey {
        if (x.len != p256_coord_len or y.len != p256_coord_len) return error.BadLength;
        var out: PublicKey = .{ .p256 = .{ .x = undefined, .y = undefined } };
        @memcpy(&out.p256.x, x);
        @memcpy(&out.p256.y, y);
        return out;
    }

    pub fn p256FromUncompressed(point: []const u8) KeyError!PublicKey {
        if (point.len != p256_uncompressed_len) return error.BadLength;
        if (point[0] != 0x04) return error.NotUncompressedPoint;
        return p256FromCoordinates(point[1 .. 1 + p256_coord_len], point[1 + p256_coord_len ..]);
    }

    /// The canonical JSON of RFC 7638 section 3: required members only, in
    /// lexicographic order, no whitespace.
    pub fn canonicalJson(self: PublicKey, allocator: Allocator) KeyError![]u8 {
        switch (self) {
            .ed25519 => |x| {
                const xb = encodeBytes(allocator, &x) catch return error.OutOfMemory;
                defer allocator.free(xb);
                return std.fmt.allocPrint(allocator, "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{s}\"}}", .{xb}) catch return error.OutOfMemory;
            },
            .p256 => |coords| {
                const xb = encodeBytes(allocator, &coords.x) catch return error.OutOfMemory;
                defer allocator.free(xb);
                const yb = encodeBytes(allocator, &coords.y) catch return error.OutOfMemory;
                defer allocator.free(yb);
                return std.fmt.allocPrint(allocator, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ xb, yb }) catch return error.OutOfMemory;
            },
        }
    }

    /// The RFC 7638 thumbprint with SHA-256, base64url encoded. Used as the `kid`.
    pub fn thumbprint(self: PublicKey, allocator: Allocator) KeyError![]u8 {
        const canon = try self.canonicalJson(allocator);
        defer allocator.free(canon);
        var hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(canon, &hash, .{});
        return encodeBytes(allocator, &hash) catch return error.OutOfMemory;
    }
};

fn encodeBytes(allocator: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    return b64url.encode(allocator, bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Encoding raw bytes cannot fail the alphabet/length/canonical checks.
        else => unreachable,
    };
}

test "rfc8037 a3 thumbprint" {
    const x_b64 = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const x = try b64url.decode(testing.allocator, x_b64);
    defer testing.allocator.free(x);
    const key = try PublicKey.ed25519FromBytes(x);
    const canon = try key.canonicalJson(testing.allocator);
    defer testing.allocator.free(canon);
    try testing.expectEqualStrings(
        "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}",
        canon,
    );
    const tp = try key.thumbprint(testing.allocator);
    defer testing.allocator.free(tp);
    try testing.expectEqualStrings("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", tp);
}

test "p256 thumbprint" {
    const px = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
    const py = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";
    const x = try b64url.decode(testing.allocator, px);
    defer testing.allocator.free(x);
    const y = try b64url.decode(testing.allocator, py);
    defer testing.allocator.free(y);
    const key = try PublicKey.p256FromCoordinates(x, y);
    const tp = try key.thumbprint(testing.allocator);
    defer testing.allocator.free(tp);
    try testing.expectEqualStrings("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", tp);
}

test "rejects wrong lengths" {
    try testing.expectError(error.BadLength, PublicKey.ed25519FromBytes(&[_]u8{0} ** 31));
    try testing.expectError(error.BadLength, PublicKey.p256FromCoordinates(&[_]u8{0} ** 32, &[_]u8{0} ** 33));
    try testing.expectError(error.NotUncompressedPoint, PublicKey.p256FromUncompressed(&[_]u8{0} ** 65));
}
