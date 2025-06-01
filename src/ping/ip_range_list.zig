const std = @import("std");
const ip = @import("ip.zig");
const ipRange = @import("ip_range.zig");

const Ip = ip.Ip;
const IpRange = ipRange.IpRange;

pub const IpRangeList = struct {
    ipRanges: std.ArrayList(IpRange),

    pub fn init(allocator: std.mem.Allocator) IpRangeList {
        return IpRangeList{
            .ipRanges = std.ArrayList(IpRange).init(allocator),
        };
    }

    pub fn includeRange(self: *IpRangeList, include: IpRange) !void {
        try self.ipRanges.append(include);
        self.merge();
        self.sort();
    }

    pub fn excludeRange(self: *IpRangeList, exclude: IpRange) !void {
        const excludeBegin = exclude.begin.value;
        const excludeEnd = exclude.end.value;

        var i: usize = 0;
        while (i < self.ipRanges.items.len) {
            const current = self.ipRanges.items[i];
            const currentBegin = current.begin.value;
            const currentEnd = current.end.value;

            // No overlap
            if (excludeEnd < currentBegin or excludeBegin > currentEnd) {
                i += 1;
                continue;
            }

            // Full containment — remove
            if (excludeBegin <= currentBegin and excludeEnd >= currentEnd) {
                _ = self.ipRanges.orderedRemove(i);
                continue;
            }

            // Overlaps at the beginning — trim start
            if (excludeBegin <= currentBegin and excludeEnd < currentEnd) {
                self.ipRanges.items[i].begin.value = excludeEnd + 1;
                i += 1;
                continue;
            }

            // Overlaps at the end — trim end
            if (excludeBegin > currentBegin and excludeEnd >= currentEnd) {
                self.ipRanges.items[i].end.value = excludeBegin - 1;
                i += 1;
                continue;
            }

            // Middle overlap — split into two
            if (excludeBegin > currentBegin and excludeEnd < currentEnd) {
                const new_range = IpRange{
                    .begin = Ip.init(excludeEnd + 1),
                    .end = Ip.init(currentEnd),
                };
                self.ipRanges.items[i].end.value = excludeBegin - 1;
                try self.ipRanges.insert(i + 1, new_range);
                i += 2;
                continue;
            }

            // Impossible, but just in case
            i += 1;
        }
        self.merge();
        self.sort();
    }

    pub fn getIpByIndex(self: *const IpRangeList, i: usize) Ip {
        var offset: u32 = 0;
        for (self.ipRanges.items) |r| {
            const size = r.end.value - r.begin.value + 1;
            if (i < offset + size) {
                return Ip.init(r.begin.value + (@as(u32, @intCast(i)) - offset));
            }
            offset += size;
        }
        unreachable;
    }

    pub fn getIpCount(self: *const IpRangeList) usize {
        var total: usize = 0;
        for (self.ipRanges.items) |r| {
            total += r.end.value - r.begin.value + 1;
        }
        return total;
    }

    fn sort(self: *IpRangeList) void {
        std.mem.sort(IpRange, self.ipRanges.items, {}, struct {
            pub fn lessThan(_: void, a: IpRange, b: IpRange) bool {
                return a.begin.value < b.begin.value;
            }
        }.lessThan);
    }

    fn merge(self: *IpRangeList) void {
        var i: usize = 0;
        while (i + 1 < self.ipRanges.items.len) {
            const current = self.ipRanges.items[i];
            const next = self.ipRanges.items[i + 1];

            if (current.end.value + 1 >= next.begin.value) {
                // Ranges overlap or touch — merge
                self.ipRanges.items[i].end.value = @max(current.end.value, next.end.value);
                _ = self.ipRanges.orderedRemove(i + 1);
            } else {
                i += 1;
            }
        }
    }
};

fn testExpectedRange(
    actual: IpRange,
    expectedBegin: []const u8,
    expectedEnd: []const u8,
    allocator: std.mem.Allocator,
) !void {
    const begin_str = try actual.begin.toString(allocator);
    const end_str = try actual.end.toString(allocator);
    defer allocator.free(begin_str);
    defer allocator.free(end_str);

    try std.testing.expectEqualStrings(expectedBegin, begin_str);
    try std.testing.expectEqualStrings(expectedEnd, end_str);
}

test "include two adjacent ranges and merge" {
    const allocator = std.testing.allocator;
    var list = IpRangeList.init(allocator);
    defer list.ipRanges.deinit();

    try list.includeRange(try IpRange.fromCidr("192.168.1.0/25")); // 0–127
    try list.includeRange(try IpRange.fromCidr("192.168.1.128/25")); // 128–255

    try std.testing.expectEqual(@as(usize, 1), list.ipRanges.items.len);
    try testExpectedRange(
        list.ipRanges.items[0],
        "192.168.1.0",
        "192.168.1.255",
        allocator,
    );
}

test "include overlapping ranges and merge" {
    const allocator = std.testing.allocator;
    var list = IpRangeList.init(allocator);
    defer list.ipRanges.deinit();

    try list.includeRange(try IpRange.fromCidr("10.0.0.0/24")); // 0–255
    try list.includeRange(try IpRange.fromCidr("10.0.0.128/25")); // 128–255

    try std.testing.expectEqual(@as(usize, 1), list.ipRanges.items.len);
    try testExpectedRange(
        list.ipRanges.items[0],
        "10.0.0.0",
        "10.0.0.255",
        allocator,
    );
}

test "include disjoint ranges, no merge" {
    const allocator = std.testing.allocator;
    var list = IpRangeList.init(allocator);
    defer list.ipRanges.deinit();

    try list.includeRange(try IpRange.fromCidr("10.0.0.0/25")); // 0–127
    try list.includeRange(try IpRange.fromCidr("10.0.1.0/25")); // 256–383

    try std.testing.expectEqual(@as(usize, 2), list.ipRanges.items.len);
    try testExpectedRange(list.ipRanges.items[0], "10.0.0.0", "10.0.0.127", allocator);
    try testExpectedRange(list.ipRanges.items[1], "10.0.1.0", "10.0.1.127", allocator);
}

test "exclude middle part of a range" {
    const allocator = std.testing.allocator;
    var list = IpRangeList.init(allocator);
    defer list.ipRanges.deinit();

    try list.includeRange(try IpRange.fromCidr("192.168.0.0/24")); // 0–255

    const exclude = IpRange{ // 100-250
        .begin = Ip.init(192 << 24 | 168 << 16 | 0 << 8 | 100),
        .end = Ip.init(192 << 24 | 168 << 16 | 0 << 8 | 150),
    };
    try list.excludeRange(exclude);

    try std.testing.expectEqual(@as(usize, 2), list.ipRanges.items.len);
    try testExpectedRange(list.ipRanges.items[0], "192.168.0.0", "192.168.0.99", allocator);
    try testExpectedRange(list.ipRanges.items[1], "192.168.0.151", "192.168.0.255", allocator);
}

test "exclude entire range" {
    const allocator = std.testing.allocator;
    var list = IpRangeList.init(allocator);
    defer list.ipRanges.deinit();

    try list.includeRange(try IpRange.fromCidr("10.0.0.0/24")); // 0–255

    const exclude = try IpRange.fromCidr("10.0.0.0/24");
    try list.excludeRange(exclude);

    try std.testing.expectEqual(@as(usize, 0), list.ipRanges.items.len);
}

test "exclude overlapping start of range" {
    const allocator = std.testing.allocator;
    var list = IpRangeList.init(allocator);
    defer list.ipRanges.deinit();

    try list.includeRange(try IpRange.fromCidr("10.0.0.0/24")); // 0–255

    const exclude = IpRange{
        .begin = Ip.init(0),
        .end = Ip.init(10 << 24 | 0 << 16 | 0 << 8 | 100),
    };
    try list.excludeRange(exclude);

    try std.testing.expectEqual(@as(usize, 1), list.ipRanges.items.len);
    try testExpectedRange(list.ipRanges.items[0], "10.0.0.101", "10.0.0.255", allocator);
}

test "exclude overlapping end of range" {
    const allocator = std.testing.allocator;
    var list = IpRangeList.init(allocator);
    defer list.ipRanges.deinit();

    try list.includeRange(try IpRange.fromCidr("10.0.0.0/24")); // 0–255

    const exclude = IpRange{ // 200–255
        .begin = Ip.init(10 << 24 | 0 << 16 | 0 << 8 | 200),
        .end = Ip.init(255 << 24 | 255 << 16 | 255 << 8 | 255),
    };
    try list.excludeRange(exclude);

    try std.testing.expectEqual(@as(usize, 1), list.ipRanges.items.len);
    try testExpectedRange(list.ipRanges.items[0], "10.0.0.0", "10.0.0.199", allocator);
}
