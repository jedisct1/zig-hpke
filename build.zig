const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bounded_array_module = b.dependency("bounded_array", .{}).module("bounded_array");

    const lib = b.addStaticLibrary(.{
        .name = "hpke",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.addModule("bounded_array", bounded_array_module);
    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/tests.zig" },
        .target = target,
        .optimize = optimize,
    });
    main_tests.addModule("bounded_array", bounded_array_module);

    const main_tests_run = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests_run.step);
}
