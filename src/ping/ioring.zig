const std = @import("std");
const crypto = @import("crypto.zig");
const IpRangeList = @import("ip_range_list.zig").IpRangeList;
const icmp_header = @import("icmp.zig");

const IcmpHeader = icmp_header.IcmpHeader;
const FeistelPermutation = crypto.FeistelPermutation;

const TransmitEntry = struct {
    address: std.posix.sockaddr,
    header: IcmpHeader,
    iovec: std.posix.iovec_const,
    msghdr: std.posix.msghdr_const,
};

const ReceiveEntry = struct {
    buffer: [28]u8,
    address: std.posix.sockaddr,
    address_len: std.posix.socklen_t,
    iovec: std.posix.iovec,
    msghdr: std.posix.msghdr,
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

    fn fillBatch(self: *BatchProcessor, batch_buffer: []TransmitEntry) usize {
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

        const ring = try std.os.linux.IoUring.init(batch_size, std.os.linux.IORING_FEAT_SQPOLL_NONFIXED);
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
        const batch_buffer = try allocator.alloc(TransmitEntry, self.batch_size);
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

            const stdout = std.io.getStdOut().writer();
            try stdout.print("Packets: {} | Rate: {d:.2} pps | Throughput: {d:.2} MB/s ({d:.2} Mbps)\n", .{
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

        const stdout = std.io.getStdOut().writer();
        try stdout.print("=== FINAL STATS ===\n", .{});
        try stdout.print("Total packets sent: {}\n", .{self.packets_sent});
        try stdout.print("Total bytes sent: {}\n", .{self.bytes_sent});
        try stdout.print("Total time: {d:.2}s\n", .{elapsed_total});
        try stdout.print("Average rate: {d:.2} packets/sec\n", .{total_packets_per_sec});
        try stdout.print("Average throughput: {d:.2} MB/s ({d:.2} Mbps)\n", .{
            total_bytes_per_sec / (1024.0 * 1024.0),
            total_mbps,
        });
    }

    pub fn receiveLoop(self: *IoRing, allocator: std.mem.Allocator) !void {
        _ = self;
        _ = allocator;
        // const receive_buffer = try allocator.alloc(ReceiveEntry, self.batch_size);
        // defer allocator.free(receive_buffer);

        // for (receive_buffer) |*entry| {
        // @memset(&entry.buffer, 0);
        // @memset(@as([*]u8, @ptrCast(&entry.address))[0..@sizeOf(std.posix.sockaddr)], 0);

        // entry.address_len = @sizeOf(std.posix.sockaddr);
        // entry.iovec = std.posix.iovec{
        //     .base = @ptrCast(&entry.buffer),
        //     .len = entry.buffer.len,
        // };

        // }
        // const local = struct {
        //     var msg: std.posix.msghdr = .{
        //         .name = null,
        //         .namelen = 0,
        //         .iov = undefined,
        //         .iovlen = 0,
        //         .control = null,
        //         .controllen = 0,
        //         .flags = 0,
        //     };
        // };

        // var sqe = try self.ring.recvmsg(0, self.socket, &local.msg, 0);
        // sqe.flags |= std.os.linux.IOSQE_BUFFER_SELECT | std.os.linux.IOSQE_FIXED_FILE;
        // sqe.ioprio |= std.os.linux.IORING_RECV_MULTISHOT;
        // sqe.buf_index = 0;
        // _ = try self.ring.submit();

        // while (true) {
        //     var completed: u32 = 0;
        //     while (completed < submitted) {
        //         const cq_ready = self.ring.cq_ready();
        //         if (cq_ready == 0) break;

        //         for (0..cq_ready) |i| {
        //             const cqe = self.ring.cq.cqes[i];
        //             completed += 1;

        //             switch (std.posix.errno(@as(isize, @intCast(cqe.res)))) {
        //                 .SUCCESS => {
        //                     const bytes_received = @as(usize, @intCast(cqe.res));
        //                     try self.processReceivedPacket(receive_buffer[i].buffer[0..bytes_received]);
        //                 },
        //                 .AGAIN => continue, // No data available, continue
        //                 .INTR => continue, // Interrupted, continue
        //                 else => |err| {
        //                     std.log.warn("Receive error: {}", .{err});
        //                     continue;
        //                 },
        //             }
        //         }
        //     }
        // }
    }
    fn processReceivedPacket(self: *IoRing, packet_data: []const u8) !void {
        _ = self;

        if (packet_data.len < 20) { // Minimum IP header size
            return; // Packet too small
        }

        // Skip IP header (assume 20 bytes for simplicity, could parse IHL for exact size)
        const ip_header_len = 20;
        if (packet_data.len < ip_header_len + @sizeOf(IcmpHeader)) {
            return;
        }

        const icmp_data = packet_data[ip_header_len..];
        const icmp_header_ptr = @as(*const IcmpHeader, @ptrCast(@alignCast(icmp_data.ptr)));

        // Extract source IP from the IP header, not from source_addr which might be corrupted
        const ip_header = packet_data[0..20];
        const src_ip_bytes = ip_header[12..16];

        if (src_ip_bytes[0] == 8) {
            std.log.err("Received ICMP from {}.{}.{}.{}: type={}, code={}", .{
                src_ip_bytes[0],      src_ip_bytes[1],      src_ip_bytes[2], src_ip_bytes[3],
                icmp_header_ptr.type, icmp_header_ptr.code,
            });
        }
    }
};
