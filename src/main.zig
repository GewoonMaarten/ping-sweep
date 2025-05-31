const std = @import("std");
const icmp_socket = @import("icmp/icmp_socket.zig");
const icmp_header = @import("icmp/icmp_header.zig");

pub fn main() !void {
    std.debug.print("Hello, {s}!\n", .{"World"});

    const icmpSocket = try icmp_socket.IcmpSocket.init();
    const icmpHeader = icmp_header.IcmpHeader.init(0, 0);

    const addr = try std.net.Address.parseIp4("8.8.8.8", 0);
    try icmpSocket.sendTo(icmpHeader, addr);
}
