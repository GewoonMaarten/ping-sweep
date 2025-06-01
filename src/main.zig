const std = @import("std");
// const icmp_socket = @import("icmp/icmp_socket.zig");
// const icmp_header = @import("icmp/icmp_header.zig");

const ping = @import("ping.zig");

pub fn main() !void {
    std.debug.print("Hello, {s}!\n", .{"World"});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var ipRangeList = ping.IpRangeList.init(allocator);
    defer ipRangeList.ipRanges.deinit();

    const whitelistBuffer = try std.fs.cwd().readFileAlloc(
        allocator,
        "whitelist.txt",
        4096,
    );
    defer allocator.free(whitelistBuffer);

    std.debug.print("include list:\n", .{});

    var offset: usize = 0;
    for (whitelistBuffer, 0..) |ch, i| {
        if (ch == '\n') {
            const ipRange = try ping.IpRange.fromCidr(whitelistBuffer[offset..i]);
            try ipRangeList.includeRange(ipRange);

            const beginIpString = try ipRange.begin.toString(allocator);
            defer allocator.free(beginIpString);
            const endIpString = try ipRange.end.toString(allocator);
            defer allocator.free(endIpString);

            std.debug.print("\tbegin ip: {s}, end ip: {s}\n", .{ beginIpString, endIpString });

            offset = i + 1;
        }
    }

    const blacklistBuffer = try std.fs.cwd().readFileAlloc(
        allocator,
        "blacklist.txt",
        4096,
    );
    defer allocator.free(blacklistBuffer);

    std.debug.print("exclude list:\n", .{});

    offset = 0;
    for (blacklistBuffer, 0..) |ch, i| {
        if (ch == '\n') {
            const ipRange = try ping.IpRange.fromCidr(blacklistBuffer[offset..i]);
            try ipRangeList.excludeRange(ipRange);

            const beginIpString = try ipRange.begin.toString(allocator);
            defer allocator.free(beginIpString);
            const endIpString = try ipRange.end.toString(allocator);
            defer allocator.free(endIpString);

            std.debug.print("\tbegin ip: {s}, end ip: {s}\n", .{ beginIpString, endIpString });

            offset = i + 1;
        }
    }

    std.debug.print("range list includes: {d} IPs\n", .{ipRangeList.getIpCount()});

    const totalIps = ipRangeList.getIpCount();
    const feistelPermutation = ping.crypto.FeistelPermutation.init(
        4,
        totalIps,
        ping.crypto.getSeed(),
    );

    for (0..totalIps) |index| {
        const newIndex = feistelPermutation.shuffle(index);
        const pickedIp = ipRangeList.getIpByIndex(newIndex);
        const picketIpString = try pickedIp.toString(allocator);
        defer allocator.free(picketIpString);
        std.debug.print("chosen IP: {s}\n", .{picketIpString});
    }

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
}
