const std = @import("std");

pub const Ip = struct {
    value: u32,
    inner: std.net.Address,

    pub fn init(address: u32) Ip {
        var buffer: [4]u8 = undefined;
        std.mem.writeInt(u32, &buffer, address, .big);
        const ip_address = std.net.Address.initIp4(buffer, 0);
        return Ip{
            .value = std.mem.nativeToBig(u32, ip_address.in.sa.addr),
            .inner = ip_address,
        };
    }

    pub fn fromBuffer(buffer: []const u8) !Ip {
        const ip_address = try std.net.Address.parseIp4(buffer, 0);
        return Ip{
            .value = std.mem.nativeToBig(u32, ip_address.in.sa.addr),
            .inner = ip_address,
        };
    }

    pub fn format(
        ip: Ip,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const bytes = @as([4]u8, @bitCast(ip.value));
        _ = try writer.print("{d}.{d}.{d}.{d}", .{ bytes[3], bytes[2], bytes[1], bytes[0] });
    }
};

test "Ip toString" {
    const allocator = std.testing.allocator_instance.allocator();
    const ip = try Ip.fromBuffer("1.2.3.4");
    const ipString = try ip.toString(allocator);
    defer allocator.free(ipString);
    try std.testing.expectEqualDeep("1.2.3.4", ipString);
}
