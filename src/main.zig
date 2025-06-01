const std = @import("std");
// const icmp_socket = @import("icmp/icmp_socket.zig");
// const icmp_header = @import("icmp/icmp_header.zig");

const ping = @import("ping.zig");

pub fn main() !void {
    std.debug.print("Hello, {s}!\n", .{"World"});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    // const icmpSocket = try icmp_socket.IcmpSocket.init();
    // const icmpHeader = icmp_header.IcmpHeader.init(0, 0);

    // for (0..256) |_i| {
    //     const i = @as(u8, @intCast(_i));
    //     const addr = std.net.Address.initIp4([4]u8{ 8, 8, 8, i }, 0);
    //     try icmpSocket.sendTo(icmpHeader, addr);
    // }

    // const addr = std.net.Address.initIp4([4]u8{ 8, 8, 8, 8 }, 0);
    // try icmpSocket.sendTo(icmpHeader, addr);

    // const x = try icmpSocket.recv();
    // _ = x;

    const buffer = try std.fs.cwd().readFileAlloc(
        allocator,
        "whitelist.txt",
        4096,
    );
    defer allocator.free(buffer);

    var offset: usize = 0;
    for (buffer, 0..) |ch, i| {
        if (ch == '\n') {
            const ipRange = try ping.IpRange.fromCidr(buffer[offset..i]);

            const beginIpString = try ipRange.begin.toString(allocator);
            defer allocator.free(beginIpString);
            const endIpString = try ipRange.end.toString(allocator);
            defer allocator.free(endIpString);

            std.debug.print("begin ip: {s}, end ip: {s}\n", .{ beginIpString, endIpString });

            offset = i + 1;
        }

        // std.debug.print("{c}", .{ch});
    }
}
