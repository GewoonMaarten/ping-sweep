const std = @import("std");
const ip = @import("ip.zig");

const Ip = ip.Ip;

pub const IcmpHeader = extern struct {
    type: u8 = 8,
    code: u8 = 0,
    checksum: u16 = 0,
    id: u16,
    seq: u16,

    pub fn init(id: u16, seq: u16) IcmpHeader {
        var header = IcmpHeader{ .id = id, .seq = seq };
        header.calcChecksum();
        return header;
    }

    fn calcChecksum(self: *IcmpHeader) void {
        var sum: u32 = 0;
        const words = std.mem.bytesAsSlice(u16, std.mem.asBytes(self));
        for (words) |w| sum += w;
        while (sum > 0xFFFF) sum = (sum >> 16) + (sum & 0xFFFF);
        self.checksum = ~@as(u16, @truncate(sum));
    }
};

test "IcmpHeader" {
    var header = IcmpHeader{ .id = 0x1234, .seq = 0x5678 };
    header.calcChecksum();

    try std.testing.expectEqual(8, header.type);
    try std.testing.expectEqual(0, header.code);
    try std.testing.expectEqual(0x1234, header.id);
    try std.testing.expectEqual(0x5678, header.seq);

    header.calcChecksum();
    try std.testing.expectEqual(0, header.checksum);
}
