//! Edge-auth JWT verify sidecar (ADR 0007).
//!
//! Usage:
//!   zig-out/bin/authcraft-edge --jwks jwks.json --policy policy.json [--listen 127.0.0.1:8091]

const std = @import("std");
const net = std.net;
const http = std.http;
const sidecar_verify = @import("sidecar_verify.zig");
const c_api = @import("c_api.zig");

const default_listen = "127.0.0.1:8091";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var jwks_path: ?[]const u8 = null;
    var policy_path: ?[]const u8 = null;
    var listen_addr: []const u8 = default_listen;

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // argv0
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--jwks")) {
            jwks_path = args.next() orelse return usageError();
        } else if (std.mem.eql(u8, arg, "--policy")) {
            policy_path = args.next() orelse return usageError();
        } else if (std.mem.eql(u8, arg, "--listen")) {
            listen_addr = args.next() orelse return usageError();
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printUsage();
            return;
        } else {
            return usageError();
        }
    }

    const jwks_file = jwks_path orelse return usageError();
    const policy_file = policy_path orelse return usageError();

    const jwks = try std.fs.cwd().readFileAlloc(allocator, jwks_file, 1 << 20);
    defer allocator.free(jwks);
    const policy = try std.fs.cwd().readFileAlloc(allocator, policy_file, 1 << 16);
    defer allocator.free(policy);

    const address = try parseListen(listen_addr);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    std.log.info("authcraft-edge listening on {s}", .{listen_addr});

    var read_buffer: [8192]u8 = undefined;
    while (true) {
        const conn = try server.accept();
        defer conn.stream.close();
        var http_server = http.Server.init(conn, &read_buffer);
        while (http_server.state == .ready) {
            var request = http_server.receiveHead() catch |err| switch (err) {
                error.HttpConnectionClosing => break,
                else => {
                    std.log.warn("receiveHead: {s}", .{@errorName(err)});
                    break;
                },
            };
            try handleRequest(&request, jwks, policy);
        }
    }
}

fn usageError() error{Usage} {
    printUsage() catch {};
    return error.Usage;
}

fn printUsage() !void {
    const out = std.io.getStdErr().writer();
    try out.writeAll(
        \\authcraft-edge — JWT verify sidecar (ADR 0007)
        \\
        \\Options:
        \\  --jwks PATH       JWKS JSON (jose-cli shape)
        \\  --policy PATH     Policy JSON (jose-cli shape)
        \\  --listen HOST:PORT  default 127.0.0.1:8091
        \\
        \\Routes: GET /healthz, GET /verify (Authorization: Bearer …)
        \\
    );
}

fn parseListen(spec: []const u8) !net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.InvalidListen;
    const host = spec[0..colon];
    const port_str = spec[colon + 1 ..];
    const port = try std.fmt.parseInt(u16, port_str, 10);
    return net.Address.resolveIp(host, port);
}

fn handleRequest(request: *http.Server.Request, jwks: []const u8, policy: []const u8) !void {
    const target = request.head.target;
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;

    if (request.head.method == .GET and std.mem.eql(u8, path, "/healthz")) {
        try request.respond("ok\n", .{ .status = .ok });
        return;
    }

    if (request.head.method == .GET and std.mem.eql(u8, path, "/verify")) {
        const auth = headerValue(request, "authorization");
        const token = sidecar_verify.extractBearer(auth) orelse {
            try respondJson(request, .unauthorized, "{\"error\":\"invalid_request\"}\n");
            return;
        };

        var result: c_api.VerifyResult = undefined;
        const out = sidecar_verify.verifyBearer(token, jwks, policy, &result);
        if (out.status == 200) {
            var body_buf: [256]u8 = undefined;
            const body = try std.fmt.bufPrint(
                &body_buf,
                "{{\"kid\":\"{s}\",\"alg\":\"{s}\"}}\n",
                .{ out.kid, out.alg },
            );
            try request.respond(body, .{
                .status = .ok,
                .extra_headers = &.{
                    .{ .name = "content-type", .value = "application/json" },
                    .{ .name = "x-authcraft-kid", .value = out.kid },
                    .{ .name = "x-authcraft-alg", .value = out.alg },
                },
            });
        } else {
            var body_buf: [128]u8 = undefined;
            const body = try std.fmt.bufPrint(
                &body_buf,
                "{{\"error\":\"{s}\"}}\n",
                .{out.error_code},
            );
            try respondJson(request, .unauthorized, body);
        }
        return;
    }

    try request.respond("not found\n", .{ .status = .not_found });
}

fn respondJson(request: *http.Server.Request, status: http.Status, body: []const u8) !void {
    try request.respond(body, .{
        .status = status,
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
        },
    });
}

fn headerValue(request: *http.Server.Request, name: []const u8) ?[]const u8 {
    var it = request.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}
