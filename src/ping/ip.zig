const std = @import("std");

pub const Ip = struct {
    value: u32,

    pub fn init(address: u32) Ip {
        return Ip{ .value = address };
    }

    pub fn fromBuffer(buffer: []const u8) !Ip {
        const ipAddress = try std.net.Ip4Address.parse(buffer, 0);
        return Ip{ .value = std.mem.nativeToBig(u32, ipAddress.sa.addr) };
    }

    pub fn toString(self: *const Ip, allocator: std.mem.Allocator) ![]u8 {
        const bytes = @as([4]u8, @bitCast(self.value));
        const ipString = try std.fmt.allocPrint(
            allocator,
            "{d}.{d}.{d}.{d}",
            .{ bytes[3], bytes[2], bytes[1], bytes[0] },
        );
        return ipString;
    }
};

test "Ip toString" {
    const allocator = std.testing.allocator_instance.allocator();
    const ip = try Ip.fromBuffer("1.2.3.4");
    const ipString = try ip.toString(allocator);
    defer allocator.free(ipString);
    try std.testing.expectEqualDeep("1.2.3.4", ipString);
}
