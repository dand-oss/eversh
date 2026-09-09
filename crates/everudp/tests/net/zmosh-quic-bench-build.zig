const std = @import("std");
const build_zig_zon = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    options.addOption([]const u8, "version", @as([]const u8, build_zig_zon.version));
    options.addOption([]const u8, "ghostty_version", build_zig_zon.dependencies.ghostty.hash);
    options.addOption(
        []const u8,
        "ghostty_commit",
        "6361b2eac73e8243a7042f517ea95ab87165f105",
    );

    const module = b.createModule(.{
        .root_source_file = b.path("zmosh-quic-bridge.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addOptions("build_options", options);

    const ghostty = b.dependency("ghostty", .{
        .target = target,
        .optimize = optimize,
        .@"emit-lib-vt" = true,
        .@"vt-features" = "+snapshot",
        .@"emit-xcframework" = false,
        .@"emit-macos-app" = false,
    });
    module.addImport("ghostty-vt", ghostty.module("ghostty-vt"));
    const quicz = b.dependency("quicz", .{ .target = target, .optimize = optimize });
    module.addImport("quicz", quicz.module("quicz"));

    const executable = b.addExecutable(.{
        .name = "zmosh-quic-bridge",
        .root_module = module,
    });
    b.installArtifact(executable);
    const tests = b.addTest(.{ .root_module = module, .filters = &.{"bridge queued input"} });
    b.step("test", "Check benchmark bridge input scheduling").dependOn(&b.addRunArtifact(tests).step);
}
