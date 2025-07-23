const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ping_module = b.addModule("ping", .{
        .root_source_file = b.path("src/ping/ping.zig"),
    });

    const programs = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "ping-masscan", .path = "src/ping-masscan/main.zig" },
    };

    for (programs) |program| {
        const exe = b.addExecutable(.{
            .name = program.name,
            .root_source_file = b.path(program.path),
            .target = target,
            .optimize = optimize,
        });

        exe.root_module.addImport("ping", ping_module);
        exe.linkLibC();

        b.installArtifact(exe);
    }
}
