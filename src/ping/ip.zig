const std = @import("std");

pub const IpHeader = extern struct {
    /// Version (4 bits) + IHL (4 bits)
    version_ihl: u8,
    /// Type of service
    type_of_service: u8,
    /// Total length (network byte order)
    total_length: u16,
    /// Identification (network byte order)
    identification: u16,
    /// Flags (3 bits) + Fragment offset (13 bits) (network byte order)
    flags_fragment: u16,
    /// Time to live
    ttl: u8,
    /// Protocol
    protocol: u8,
    /// Header checksum (network byte order)
    header_checksum: u16,
    /// Source IP address (network byte order)
    source_addr: u32,
    /// Destination IP address (network byte order)
    dest_addr: u32,

    pub fn getVersion(self: *const IpHeader) u4 {
        return @truncate(self.version_ihl >> 4);
    }

    pub fn getHeaderLength(self: *const IpHeader) u4 {
        return @truncate(self.version_ihl & 0x0F);
    }

    pub fn getHeaderLengthBytes(self: *const IpHeader) u8 {
        const ihl = self.getHeaderLength();
        return @as(u8, ihl) * 4;
    }

    pub fn getTotalLength(self: *const IpHeader) u16 {
        return std.mem.bigToNative(u16, self.total_length);
    }

    pub fn getSourceIp(self: *const IpHeader) [4]u8 {
        const addr = std.mem.bigToNative(u32, self.source_addr);
        return [4]u8{
            @truncate(addr >> 24),
            @truncate(addr >> 16),
            @truncate(addr >> 8),
            @truncate(addr),
        };
    }

    pub fn getDestIp(self: *const IpHeader) [4]u8 {
        const addr = std.mem.bigToNative(u32, self.dest_addr);
        return [4]u8{
            @truncate(addr >> 24),
            @truncate(addr >> 16),
            @truncate(addr >> 8),
            @truncate(addr),
        };
    }
};

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
