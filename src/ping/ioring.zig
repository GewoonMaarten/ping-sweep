const std = @import("std");
const crypto = @import("crypto.zig");
const IpRangeList = @import("ip_range_list.zig").IpRangeList;
const icmp_header = @import("icmp.zig");

const IcmpHeader = icmp_header.IcmpHeader;
const FeistelPermutation = crypto.FeistelPermutation;

const BatchEntry = struct {
    address: std.posix.sockaddr,
    header: IcmpHeader,
    iovec: std.posix.iovec_const,
    msghdr: std.posix.msghdr_const,
};

pub const BatchProcessor = struct {
    feistel_permutation: FeistelPermutation,
    ip_range_list: IpRangeList,
    packets_remaining: u32,
    packets_processed: u32,

    pub fn init(ip_range_list: IpRangeList) BatchProcessor {
        const total_ips = ip_range_list.getIpCount();
        const feistel_permutation = FeistelPermutation.init(
            4,
            total_ips,
            crypto.getSeed(),
        );
        return BatchProcessor{
            .feistel_permutation = feistel_permutation,
            .ip_range_list = ip_range_list,
            .packets_remaining = @as(u32, @intCast(total_ips)),
            .packets_processed = 0,
        };
    }

    fn fillBatch(self: *BatchProcessor, batch_buffer: []BatchEntry) usize {
        const count = @min(batch_buffer.len, self.packets_remaining);

        for (0..count) |i| {
            const idx = self.packets_processed + i;
            const new_idx = self.feistel_permutation.shuffle(idx);
            const picked_ip = self.ip_range_list.getIpByIndex(new_idx);

            batch_buffer[i].address = picked_ip.inner.any;
            batch_buffer[i].header = IcmpHeader.init(0, 0);
            batch_buffer[i].iovec = std.posix.iovec_const{
                .base = @ptrCast(&batch_buffer[i].header),
                .len = @sizeOf(IcmpHeader),
            };

            batch_buffer[i].msghdr = std.posix.msghdr_const{
                .name = @ptrCast(&batch_buffer[i].address),
                .namelen = @sizeOf(std.posix.sockaddr.in),
                .iov = @ptrCast(&batch_buffer[i].iovec),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
        }

        self.packets_remaining -= @as(u32, @intCast(count));
        self.packets_processed += @as(u32, @intCast(count));
        return count;
    }
};

pub const IoRing = struct {
    ring: std.os.linux.IoUring,
    socket: std.os.linux.fd_t,
    batch_size: u16 = 0,

    // Metrics
    packets_sent: u64 = 0,
    bytes_sent: u64 = 0,
    start_time: i64 = 0,
    last_log_time: i64 = 0,
    log_interval_ms: i64 = 1_000, // 1 second

    pub fn init(batch_size: u16) !IoRing {
        const socket = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.RAW,
            std.posix.IPPROTO.ICMP,
        );
        errdefer std.posix.close(socket);

        const ring = try std.os.linux.IoUring.init(batch_size, 0);
        errdefer ring.deinit();

        const now = std.time.milliTimestamp();

        return IoRing{
            .ring = ring,
            .socket = socket,
            .batch_size = batch_size,
            .start_time = now,
            .last_log_time = now,
        };
    }

    pub fn deinit(self: *IoRing) void {
        self.ring.deinit();
        std.posix.close(self.socket);
    }

    pub fn transmitLoop(self: *IoRing, batch_processor: *BatchProcessor, allocator: std.mem.Allocator) !void {
        const batch_buffer = try allocator.alloc(BatchEntry, self.batch_size);
        defer allocator.free(batch_buffer);

        while (true) {
            const packet_count = batch_processor.fillBatch(batch_buffer);
            if (packet_count == 0) break;

            for (batch_buffer[0..packet_count]) |*batch_entry| {
                _ = try self.ring.sendmsg(0, self.socket, &batch_entry.msghdr, 0);

                self.packets_sent += 1;
                self.bytes_sent += @sizeOf(std.posix.sockaddr.in) + @sizeOf(IcmpHeader);
            }

            const submitted = try self.ring.submit();
            try self.waitForCompletions(submitted);

            try self.logMetrics();
        }

        try self.logFinalMetrics();
    }

    pub fn receiveLoop(self: *const IoRing) !void {
        _ = self;
    }

    fn waitForCompletions(self: *IoRing, expected: u32) !void {
        var completed: u32 = 0;
        while (completed < expected) {
            const cq_ready = self.ring.cq_ready();
            for (0..cq_ready) |i| {
                const cqe = self.ring.cq.cqes[i];
                completed += 1;
                // code stole from std.posix.sendmsg
                switch (std.posix.errno(@as(isize, @intCast(cqe.res)))) {
                    .SUCCESS => return,

                    .ACCES => return error.AccessDenied,
                    .AGAIN => return error.WouldBlock,
                    .ALREADY => return error.FastOpenAlreadyInProgress,
                    .BADF => unreachable, // always a race condition
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .DESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
                    .FAULT => unreachable, // An invalid user space address was specified for an argument.
                    .INTR => continue,
                    .INVAL => unreachable, // Invalid argument passed.
                    .ISCONN => unreachable, // connection-mode socket was connected already but a recipient was specified
                    .MSGSIZE => return error.MessageTooBig,
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
                    .OPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
                    .PIPE => return error.BrokenPipe,
                    .AFNOSUPPORT => return error.AddressFamilyNotSupported,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .HOSTUNREACH => return error.NetworkUnreachable,
                    .NETUNREACH => return error.NetworkUnreachable,
                    .NOTCONN => return error.SocketNotConnected,
                    .NETDOWN => return error.NetworkSubsystemFailed,
                    else => |err| return std.posix.unexpectedErrno(err),
                }
            }
        }
    }

    fn logMetrics(self: *IoRing) !void {
        const now = std.time.milliTimestamp();

        if (now - self.last_log_time >= self.log_interval_ms) {
            const elapsed_total = @as(f64, @floatFromInt(now - self.start_time)) / 1_000.0;
            const total_packets_per_sec = @as(f64, @floatFromInt(self.packets_sent)) / elapsed_total;
            const total_bytes_per_sec = @as(f64, @floatFromInt(self.bytes_sent)) / elapsed_total;
            const total_mbps = (total_bytes_per_sec * 8.0) / (1024.0 * 1024.0);

            std.log.info("Packets: {} | Rate: {d:.2} pps | Throughput: {d:.2} MB/s ({d:.2} Mbps)", .{
                self.packets_sent,
                total_packets_per_sec,
                total_bytes_per_sec / (1024.0 * 1024.0),
                total_mbps,
            });

            self.last_log_time = now;
        }
    }

    fn logFinalMetrics(self: *const IoRing) !void {
        const now = std.time.milliTimestamp();
        const elapsed_total = @as(f64, @floatFromInt(now - self.start_time)) / 1_000.0;

        const total_packets_per_sec = @as(f64, @floatFromInt(self.packets_sent)) / elapsed_total;
        const total_bytes_per_sec = @as(f64, @floatFromInt(self.bytes_sent)) / elapsed_total;
        const total_mbps = (total_bytes_per_sec * 8.0) / (1024.0 * 1024.0);

        std.log.info("=== FINAL STATS ===", .{});
        std.log.info("Total packets sent: {}", .{self.packets_sent});
        std.log.info("Total bytes sent: {}", .{self.bytes_sent});
        std.log.info("Total time: {d:.2}s", .{elapsed_total});
        std.log.info("Average rate: {d:.2} packets/sec", .{total_packets_per_sec});
        std.log.info("Average throughput: {d:.2} MB/s ({d:.2} Mbps)", .{
            total_bytes_per_sec / (1024.0 * 1024.0),
            total_mbps,
        });
    }
};
