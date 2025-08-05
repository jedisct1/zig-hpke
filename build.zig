const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bounded_array = b.dependency("bounded_array", .{});

    const hpke = b.addModule("hpke", .{
        .root_source_file = b.path("src/main.zig"),
    });
    hpke.addImport("bounded_array", bounded_array.module("bounded_array"));

    const main_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    main_tests.root_module.addImport("hpke", hpke);

    const main_tests_run = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests_run.step);
}
