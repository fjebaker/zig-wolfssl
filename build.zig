const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const wolfssl = b.dependency(
        "wolfssl",
        .{
            .optimize = optimize,
            .target = target,
            .shared = false,
        },
    );
    const wolfssl_lib = wolfssl.artifact("wolfssl");

    const wolfssl_module = b.addModule("zigwolfssl", .{
        .source_file = .{ .path = "src/main.zig" },
    });

    const lib = b.addStaticLibrary(.{
        .name = "zig-wolfssl",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibrary(wolfssl_lib);

    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    main_tests.linkLibrary(wolfssl_lib);

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    const test_server = b.addExecutable(.{
        .name = "server",
        .root_source_file = .{ .path = "examples/server.zig" },
        .target = target,
        .optimize = optimize,
    });
    test_server.addModule("zigwolfssl", wolfssl_module);
    test_server.linkLibrary(wolfssl_lib);

    const run_test_server = b.addRunArtifact(test_server);

    const server_step = b.step("server", "Run test server");
    server_step.dependOn(&run_test_server.step);

    const test_client = b.addExecutable(.{
        .name = "client",
        .root_source_file = .{ .path = "examples/client.zig" },
        .target = target,
        .optimize = optimize,
    });
    test_client.addModule("zigwolfssl", wolfssl_module);
    test_client.linkLibrary(wolfssl_lib);

    const run_test_client = b.addRunArtifact(test_client);

    const client_step = b.step("client", "Run test client");
    client_step.dependOn(&run_test_client.step);
}
