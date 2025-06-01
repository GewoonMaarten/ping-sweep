const std = @import("std");
const ping = @import("ping.zig");

var isSending = true;

pub fn senderThread(
    icmpSocket: ping.IcmpSocket,
    ipRangeList: ping.IpRangeList,
    allocator: std.mem.Allocator,
) !void {
    const totalIps = ipRangeList.getIpCount();
    const feistelPermutation = ping.crypto.FeistelPermutation.init(
        4,
        totalIps,
        ping.crypto.getSeed(),
    );

    const icmpHeader = ping.IcmpHeader.init(0, 0);

    var total_bytes: usize = 0;
    var total_packets: usize = 0;
    const packet_size = @sizeOf(@TypeOf(icmpHeader));
    var timer = try std.time.Timer.start();
    var last_log_time: u64 = 0;
    const log_interval_ns = std.time.ns_per_s;

    for (0..totalIps) |index| {
        const newIndex = feistelPermutation.shuffle(index);
        const pickedIp = ipRangeList.getIpByIndex(newIndex);
        const picketIpString = try pickedIp.toString(allocator);
        defer allocator.free(picketIpString);
        // std.debug.print("chosen IP: {s}\n", .{picketIpString});

        try icmpSocket.sendTo(icmpHeader, pickedIp);

        total_packets += 1;
        total_bytes += packet_size;

        // Log statistics periodically
        const now = timer.read();
        if (now - last_log_time >= log_interval_ns) {
            const elapsed_seconds = @as(f64, @floatFromInt(now)) / std.time.ns_per_s;
            const pps = @as(f64, @floatFromInt(total_packets)) / elapsed_seconds;

            const remaining_packets = totalIps - total_packets;
            const estimated_seconds_remaining = @as(f64, @floatFromInt(remaining_packets)) / pps;
            // const estimated_completion_time = std.time.epoch.getEpochSecond() + @as(i64, @intFromFloat(estimated_seconds_remaining));

            std.debug.print(
                \\Stats: {}/{} packets ({} bytes) sent
                \\Rate: {d:.2} packets/sec
                \\ETA: {d:.1} seconds (approx {s})
                \\---
                \\
            , .{
                total_packets,
                totalIps,
                total_bytes,
                pps,
                estimated_seconds_remaining,
                std.fmt.fmtDuration(@as(u64, @intFromFloat(estimated_seconds_remaining * std.time.ns_per_s))),
                // For timestamp: std.time.epoch.EpochSeconds{ .secs = estimated_completion_time }.getDate(),
            });

            last_log_time = now;
        }
    }

    const elapsed_ns = timer.read();
    const elapsed_seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const pps = @as(f64, @floatFromInt(total_packets)) / elapsed_seconds;

    std.debug.print(
        \\=== Final Statistics ===
        \\Total IPs: {}
        \\Packets sent: {}
        \\Bytes sent: {}
        \\Elapsed time: {s}
        \\Average rate: {d:.2} packets/sec
        \\
    , .{
        totalIps,
        total_packets,
        total_bytes,
        std.fmt.fmtDuration(elapsed_ns),
        pps,
    });

    isSending = false;
}

pub fn receiverThread(icmpSocket: ping.IcmpSocket) !void {
    while (isSending) {
        const result = icmpSocket.recv();
        if (result != null) {
            _ = result.?;
            // std.debug.print("Got result: {s}\n", .{result.?});
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var ipRangeList = ping.IpRangeList.init(allocator);
    defer ipRangeList.ipRanges.deinit();

    const whitelistBuffer = try std.fs.cwd().readFileAlloc(
        allocator,
        "whitelist.txt",
        4096,
    );
    defer allocator.free(whitelistBuffer);

    std.debug.print("include list:\n", .{});

    var offset: usize = 0;
    for (whitelistBuffer, 0..) |ch, i| {
        if (ch == '\n') {
            const ipRange = try ping.IpRange.fromCidr(whitelistBuffer[offset..i]);
            try ipRangeList.includeRange(ipRange);

            const beginIpString = try ipRange.begin.toString(allocator);
            defer allocator.free(beginIpString);
            const endIpString = try ipRange.end.toString(allocator);
            defer allocator.free(endIpString);

            std.debug.print("\tbegin ip: {s}, end ip: {s}\n", .{ beginIpString, endIpString });

            offset = i + 1;
        }
    }

    const blacklistBuffer = try std.fs.cwd().readFileAlloc(
        allocator,
        "blacklist.txt",
        4096,
    );
    defer allocator.free(blacklistBuffer);

    std.debug.print("exclude list:\n", .{});

    offset = 0;
    for (blacklistBuffer, 0..) |ch, i| {
        if (ch == '\n') {
            const ipRange = try ping.IpRange.fromCidr(blacklistBuffer[offset..i]);
            try ipRangeList.excludeRange(ipRange);

            const beginIpString = try ipRange.begin.toString(allocator);
            defer allocator.free(beginIpString);
            const endIpString = try ipRange.end.toString(allocator);
            defer allocator.free(endIpString);

            std.debug.print("\tbegin ip: {s}, end ip: {s}\n", .{ beginIpString, endIpString });

            offset = i + 1;
        }
    }

    std.debug.print("range list includes: {d} IPs\n", .{ipRangeList.getIpCount()});

    const icmpSocket = try ping.IcmpSocket.init(5);
    defer std.posix.close(icmpSocket.socket);

    const x = try std.Thread.spawn(.{}, senderThread, .{ icmpSocket, ipRangeList, allocator });
    const y = try std.Thread.spawn(.{}, receiverThread, .{icmpSocket});
    x.join();
    y.join();
}
