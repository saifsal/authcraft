const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const static_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "jose",
        .root_module = lib_mod,
    });
    b.installArtifact(static_lib);

    // Shared library with the C ABI (ADR 0004).
    const shared_lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "authcraft_jose",
        .root_module = lib_mod,
    });
    b.installArtifact(shared_lib);

    b.getInstallStep().dependOn(
        &b.addInstallFile(b.path("include/authcraft_jose.h"), "include/authcraft_jose.h").step,
    );

    const unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_unit_tests.step);

    // Edge-auth JWT verify sidecar (ADR 0007).
    const sidecar_mod = b.createModule(.{
        .root_source_file = b.path("src/sidecar.zig"),
        .target = target,
        .optimize = optimize,
    });
    const sidecar_exe = b.addExecutable(.{
        .name = "authcraft-edge",
        .root_module = sidecar_mod,
    });
    b.installArtifact(sidecar_exe);
    const sidecar_step = b.step("sidecar", "Build the edge-auth verify sidecar");
    sidecar_step.dependOn(&b.addInstallArtifact(sidecar_exe, .{}).step);
}
