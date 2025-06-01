const std = @import("std");
const testing = std.testing;

pub const IcmpHeader = extern struct {
    type: u8 = 8,
    code: u8 = 0,
    checksum: u16 = 0,
    identifier: u16 = 0,
    sequence_number: u16 = 0,

    pub fn init(identifier: u16, sequence_number: u16) IcmpHeader {
        var header = IcmpHeader{
            .identifier = std.mem.nativeToBig(u16, identifier),
            .sequence_number = std.mem.nativeToBig(u16, sequence_number),
        };
        header.checksum = header.calcChecksum();
        return header;
    }

    fn calcChecksum(self: *IcmpHeader) u16 {
        var sum: u32 = 0;
        sum += @as(u32, self.type) << 8 | self.code;
        sum += std.mem.nativeToBig(u16, self.identifier);
        sum += std.mem.nativeToBig(u16, self.sequence_number);
        return std.mem.nativeToBig(u16, @truncate(~sum));
    }

    fn isCorrectChecksum(self: *const IcmpHeader) bool {
        var sum: u32 = 0;
        sum += @as(u32, self.type) << 8 | self.code;
        sum += std.mem.nativeToBig(u16, self.identifier);
        sum += std.mem.nativeToBig(u16, self.sequence_number);
        sum += std.mem.nativeToBig(u16, self.checksum);
        return sum == 0xFFFF;
    }

    // pub fn fromBytes(bytes: []const u8) !IcmpHeader {
    //     if (bytes.len < @sizeOf(IcmpHeader)) {
    //         return error.BufferTooSmall;
    //     }

    //     const header = IcmpHeader{
    //         .type = bytes[0],
    //         .code = bytes[1],
    //         .checksum = std.mem.nativeTo(u16, bytes[2..4]),
    //         .identifier = std.mem.readIntBig(u16, bytes[4..6]),
    //         .sequence_number = std.mem.readIntBig(u16, bytes[6..8]),
    //     };

    //     // if (!header.isCorrectChecksum()) {
    //     //     return error.InvalidChecksum;
    //     // }

    //     return header;
    // }

    pub fn data(self: *const IcmpHeader) []const u8 {
        return std.mem.asBytes(self);
    }
};

test "IcmpHeader initialization" {
    const header = IcmpHeader.init(0x1234, 0x5678);
    try testing.expectEqual(@as(u8, 8), header.type);
    try testing.expectEqual(@as(u8, 0), header.code);
    try testing.expectEqual(@as(u16, 0x1234), std.mem.bigToNative(u16, header.identifier));
    try testing.expectEqual(@as(u16, 0x5678), std.mem.bigToNative(u16, header.sequence_number));
    try testing.expect(header.isCorrectChecksum());
}

test "IcmpHeader checksum calculation" {
    var header = IcmpHeader{
        .type = 8,
        .code = 0,
        .identifier = std.mem.nativeToBig(u16, 0x1234),
        .sequence_number = std.mem.nativeToBig(u16, 0x5678),
    };
    header.checksum = header.calcChecksum();
    try testing.expect(header.isCorrectChecksum());
}

// test "IcmpHeader fromBytes roundtrip" {
//     const original = IcmpHeader.init(0x1234, 0x5678);
//     const bytes = original.data();

//     const parsed = try IcmpHeader.fromBytes(bytes);
//     try testing.expectEqual(original.type, parsed.type);
//     try testing.expectEqual(original.code, parsed.code);
//     try testing.expectEqual(original.checksum, parsed.checksum);
//     try testing.expectEqual(original.identifier, parsed.identifier);
//     try testing.expectEqual(original.sequence_number, parsed.sequence_number);
// }

// test "IcmpHeader fromBytes with invalid buffer" {
//     const small_buffer = [_]u8{ 1, 2, 3 }; // Too small
//     try testing.expectError(error.BufferTooSmall, IcmpHeader.fromBytes(&small_buffer));
// }

// test "IcmpHeader data method" {
//     const header = IcmpHeader.init(0x1234, 0x5678);
//     const bytes = header.data();
//     try testing.expectEqual(@sizeOf(IcmpHeader), bytes.len);
//     try testing.expectEqual(header.type, bytes[0]);
//     try testing.expectEqual(header.code, bytes[1]);
// }
