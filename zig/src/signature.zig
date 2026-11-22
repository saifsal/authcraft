//! JWS signature verification for the algorithms supported by this package.
//!
//! Verifies a signature over an already-formed JWS signing input. Compact
//! serialization, header policy, key selection and claims validation are
//! handled by higher layers. ES256 signatures use the fixed-width JOSE
//! `R || S` format, not ASN.1 DER.

const std = @import("std");
const testing = std.testing;
const alg_mod = @import("alg.zig");
const Alg = alg_mod.Alg;
const jwks = @import("jwks.zig");
const KeyMaterial = jwks.KeyMaterial;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const SignatureError = error{SignatureVerificationFailed};

/// Verifies a JWS signature over the ASCII bytes of `header.payload`.
pub fn verify(
    algorithm: Alg,
    key: KeyMaterial,
    signing_input: []const u8,
    signature_bytes: []const u8,
) SignatureError!void {
    switch (algorithm) {
        .eddsa => {
            const pk_bytes = switch (key) {
                .public => |pk| switch (pk) {
                    .ed25519 => |x| x,
                    else => return error.SignatureVerificationFailed,
                },
                else => return error.SignatureVerificationFailed,
            };
            if (signature_bytes.len != Ed25519.Signature.encoded_length) {
                return error.SignatureVerificationFailed;
            }
            var sig_arr: [Ed25519.Signature.encoded_length]u8 = undefined;
            @memcpy(&sig_arr, signature_bytes);
            const public_key = Ed25519.PublicKey.fromBytes(pk_bytes) catch {
                return error.SignatureVerificationFailed;
            };
            const sig = Ed25519.Signature.fromBytes(sig_arr);
            sig.verify(signing_input, public_key) catch {
                return error.SignatureVerificationFailed;
            };
        },
        .es256 => {
            const coords = switch (key) {
                .public => |pk| switch (pk) {
                    .p256 => |c| c,
                    else => return error.SignatureVerificationFailed,
                },
                else => return error.SignatureVerificationFailed,
            };
            if (signature_bytes.len != EcdsaP256Sha256.Signature.encoded_length) {
                return error.SignatureVerificationFailed;
            }
            var point: [65]u8 = undefined;
            point[0] = 0x04;
            @memcpy(point[1..33], &coords.x);
            @memcpy(point[33..65], &coords.y);
            const public_key = EcdsaP256Sha256.PublicKey.fromSec1(&point) catch {
                return error.SignatureVerificationFailed;
            };
            var sig_arr: [EcdsaP256Sha256.Signature.encoded_length]u8 = undefined;
            @memcpy(&sig_arr, signature_bytes);
            const sig = EcdsaP256Sha256.Signature.fromBytes(sig_arr);
            sig.verify(signing_input, public_key) catch {
                return error.SignatureVerificationFailed;
            };
        },
        .hs256 => {
            const secret = switch (key) {
                .secret => |s| s,
                else => return error.SignatureVerificationFailed,
            };
            if (secret.len < alg_mod.hs256_min_key_len) {
                return error.SignatureVerificationFailed;
            }
            if (signature_bytes.len != HmacSha256.mac_length) {
                return error.SignatureVerificationFailed;
            }
            var expected: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&expected, signing_input, secret);
            var actual: [HmacSha256.mac_length]u8 = undefined;
            @memcpy(&actual, signature_bytes);
            if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, expected, actual)) {
                return error.SignatureVerificationFailed;
            }
        },
    }
}

test "verifies hs256 signature" {
    const secret = try testing.allocator.dupe(u8, &[_]u8{0x42} ** alg_mod.hs256_min_key_len);
    defer testing.allocator.free(secret);
    const msg = "what do ya want for nothing?";
    var sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&sig, msg, secret);
    try verify(.hs256, .{ .secret = secret }, msg, &sig);
    try testing.expectError(
        error.SignatureVerificationFailed,
        verify(.hs256, .{ .secret = secret }, "tampered", &sig),
    );
}

test "verifies ed25519 signature" {
    const kp = Ed25519.KeyPair.generate();
    const msg = "eyJhbGciOiJFZERTQSJ9.e30";
    const sig = try kp.sign(msg, null);
    const sig_bytes = sig.toBytes();
    const key = KeyMaterial{ .public = .{ .ed25519 = kp.public_key.toBytes() } };
    try verify(.eddsa, key, msg, &sig_bytes);
    try testing.expectError(
        error.SignatureVerificationFailed,
        verify(.eddsa, key, msg, sig_bytes[0..63]),
    );
}

test "rejects hs256 keys shorter than 256 bits" {
    const secret = try testing.allocator.dupe(u8, &[_]u8{0x42} ** (alg_mod.hs256_min_key_len - 1));
    defer testing.allocator.free(secret);
    var sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&sig, "msg", secret);
    try testing.expectError(
        error.SignatureVerificationFailed,
        verify(.hs256, .{ .secret = secret }, "msg", &sig),
    );
}
