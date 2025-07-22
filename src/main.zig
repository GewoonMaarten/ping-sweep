const std = @import("std");
const ping = @import("ping.zig");

const IORING_BATCH_SIZE: u16 = 64;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var ip_range_list = ping.IpRangeList.init(allocator);
    defer ip_range_list.ipRanges.deinit();

    const white_list_buffer = try std.fs.cwd().readFileAlloc(
        allocator,
        "whitelist.txt",
        4096,
    );
    defer allocator.free(white_list_buffer);

    std.log.err("include list:", .{});

    var offset: usize = 0;
    for (white_list_buffer, 0..) |ch, i| {
        if (ch == '\n') {
            const ipRange = try ping.IpRange.fromCidr(white_list_buffer[offset..i]);
            try ip_range_list.includeRange(ipRange);

            std.log.err("\tbegin ip: {s}, end ip: {s}", .{ ipRange.begin, ipRange.end });

            offset = i + 1;
        }
    }

    const black_list_buffer = try std.fs.cwd().readFileAlloc(
        allocator,
        "blacklist.txt",
        4096,
    );
    defer allocator.free(black_list_buffer);

    std.log.err("exclude list:", .{});

    offset = 0;
    for (black_list_buffer, 0..) |ch, i| {
        if (ch == '\n') {
            const ipRange = try ping.IpRange.fromCidr(black_list_buffer[offset..i]);
            try ip_range_list.excludeRange(ipRange);

            std.log.err("\tbegin ip: {s}, end ip: {s}", .{ ipRange.begin, ipRange.end });

            offset = i + 1;
        }
    }

    std.log.err("range list includes: {d} IPs", .{ip_range_list.getIpCount()});

    var receive_ring = try ping.IoRing.init(IORING_BATCH_SIZE);
    defer receive_ring.deinit();
    const receive_thread = try std.Thread.spawn(.{}, ping.IoRing.receiveLoop, .{ &receive_ring, allocator });

    var processor = ping.BatchProcessor.init(ip_range_list);
    var transmit_ring = try ping.IoRing.init(IORING_BATCH_SIZE);
    defer transmit_ring.deinit();
    const transmit_thread = try std.Thread.spawn(.{}, ping.IoRing.transmitLoop, .{ &transmit_ring, &processor, allocator });

    receive_thread.join();
    transmit_thread.join();
}
