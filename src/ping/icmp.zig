const std = @import("std");

const IcmpHeader = struct {
    type: u8 = 8,
    code: u8 = 0,
    checksum: u16 = 0,
    identifier: u16 = 0,
    sequence_number: u16 = 0,

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

    pub fn init(identifier: u16, sequence_number: u16) IcmpHeader {
        var header = IcmpHeader{
            .identifier = std.mem.nativeToBig(u16, identifier),
            .sequence_number = std.mem.nativeToBig(u16, sequence_number),
        };
        header.checksum = header.calcChecksum();
        return header;
    }

    pub fn fromBytes(bytes: []const u8) !IcmpHeader {
        if (bytes.len < @sizeOf(IcmpHeader)) {
            return error.BufferTooSmall;
        }

        const header = IcmpHeader{
            .type = bytes[0],
            .code = bytes[1],
            .checksum = std.mem.readIntBig(u16, bytes[2..4]),
            .identifier = std.mem.readIntBig(u16, bytes[4..6]),
            .sequence_number = std.mem.readIntBig(u16, bytes[6..8]),
        };

        // if (!header.isCorrectChecksum()) {
        //     return error.InvalidChecksum;
        // }

        return header;
    }

    pub fn data(self: *const IcmpHeader) []const u8 {
        return std.mem.asBytes(self);
    }
};
