const std = @import("std");
const ip = @import("ip.zig");

pub const IpRange = struct {
    begin: ip.Ip,
    end: ip.Ip,

    pub fn fromCidr(buffer: []const u8) !IpRange {
        var offset: usize = 0;
        for (buffer, 0..) |ch, i| {
            // std.debug.print("char: {c}\n", .{ch});
            if (ch == '/') {
                offset = i;
            }
        }

        const ipAddress = try std.net.Ip4Address.parse(buffer[0..offset], 0);
        const suffix = try std.fmt.parseInt(u6, buffer[offset + 1 .. buffer.len], 10);

        const mask = @as(u64, 0xFFFFFFFF00000000) >> suffix;
        const begin = @as(u32, @intCast(std.mem.nativeToBig(u32, ipAddress.sa.addr) & mask));
        const end = @as(u32, @intCast(begin | (~mask & 0xFFFFFFFF)));

        // std.debug.print("ip: {d}\n", .{ipAddress.sa.addr});
        // std.debug.print("cidr suffix: {d}\n", .{suffix});
        // std.debug.print("cidr mask: {d}\n", .{mask});

        // std.debug.print("begin: {d}\n", .{begin});
        // std.debug.print("end: {d}\n", .{end});

        return IpRange{
            .begin = ip.Ip.init(begin),
            .end = ip.Ip.init(end),
        };
    }
};

test "IpRange from CIDR notation /8" {
    const allocator = std.testing.allocator_instance.allocator();

    const ipRange = try IpRange.fromCidr("10.0.0.2/8");

    const beginIpString = try ipRange.begin.toString(allocator);
    defer allocator.free(beginIpString);
    const endIpString = try ipRange.end.toString(allocator);
    defer allocator.free(endIpString);

    try std.testing.expectEqualDeep("10.0.0.0", beginIpString);
    try std.testing.expectEqualDeep("10.255.255.255", endIpString);
}
