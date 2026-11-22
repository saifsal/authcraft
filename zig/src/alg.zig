//! The JWS algorithms this project knows about.
//!
//! `none` is deliberately absent: it cannot be named, so no policy can allow it
//! (ADR 0001). Names are matched case-sensitively, so `none`, `NONE` and `eddsa`
//! are all simply unknown (ADR 0003, header rules).

const std = @import("std");
const testing = std.testing;

/// RFC 7518 section 3.2 requires HS256 keys to be at least 256 bits.
pub const hs256_min_key_len: usize = 32;

pub const Alg = enum {
    eddsa,
    es256,
    /// Verification only, to pass the RFC 7515 Appendix A.1 vector (ADR 0001).
    hs256,

    /// The registered JOSE name.
    pub fn name(self: Alg) []const u8 {
        return switch (self) {
            .eddsa => "EdDSA",
            .es256 => "ES256",
            .hs256 => "HS256",
        };
    }

    /// Looks up an algorithm by its exact, case-sensitive name.
    pub fn fromName(name_str: []const u8) ?Alg {
        if (std.mem.eql(u8, name_str, "EdDSA")) return .eddsa;
        if (std.mem.eql(u8, name_str, "ES256")) return .es256;
        if (std.mem.eql(u8, name_str, "HS256")) return .hs256;
        return null;
    }
};

test "names round trip" {
    for ([_]Alg{ .eddsa, .es256, .hs256 }) |a| {
        try testing.expectEqual(a, Alg.fromName(a.name()).?);
    }
}

test "matching is exact" {
    for ([_][]const u8{ "none", "NONE", "None", "eddsa", "EDDSA", "es256", "hs256", "RS256", "", " EdDSA", "EdDSA " }) |s| {
        try testing.expect(Alg.fromName(s) == null);
    }
}
