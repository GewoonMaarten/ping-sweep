const std = @import("std");

pub const Ip = struct {
    value: u32,
    address: std.net.Address,

    pub fn init(address: u32) Ip {
        var ipBuffer: [4]u8 = undefined;
        std.mem.writeInt(u32, &ipBuffer, address, .big);
        const ipAddress = std.net.Address.initIp4(ipBuffer, 0);
        return Ip{
            .value = std.mem.nativeToBig(u32, ipAddress.in.sa.addr),
            .address = ipAddress,
        };
    }

    pub fn fromBuffer(buffer: []const u8) !Ip {
        const ipAddress = try std.net.Address.parseIp4(buffer, 0);
        return Ip{
            .value = std.mem.nativeToBig(u32, ipAddress.in.sa.addr),
            .address = ipAddress,
        };
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
