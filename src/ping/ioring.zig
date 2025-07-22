const std = @import("std");
const crypto = @import("crypto.zig");
const IpRangeList = @import("ip_range_list.zig").IpRangeList;
const icmp_header = @import("icmp.zig");
const IpHeader = @import("./ip.zig").IpHeader;

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
            batch_buffer[i].header = IcmpHeader.init(10, 0);
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
    csv_file: ?std.fs.File = null,

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

        // Create CSV file for logging source IPs
        const csv_file = try std.fs.cwd().createFile("ping_responses.csv", .{});
        errdefer csv_file.close();
        
        // Write CSV header
        try csv_file.writeAll("timestamp,source_ip\n");

        const now = std.time.milliTimestamp();

        return IoRing{
            .ring = ring,
            .socket = socket,
            .batch_size = batch_size,
            .csv_file = csv_file,
            .start_time = now,
            .last_log_time = now,
        };
    }

    pub fn deinit(self: *IoRing) void {
        if (self.csv_file) |file| {
            file.close();
        }
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
        // _ = self;
        _ = allocator;
        const CQES = 4096;
        // const NUM_PACKETS = 1_000_000;
        const NUM_BUFFERS = 64;
        const BUFSZ = 512;

        const HDR_BUFSZ = BUFSZ + @sizeOf(std.os.linux.io_uring_recvmsg_out);
        var mega_buffer: [NUM_BUFFERS * NUM_BUFFERS * HDR_BUFSZ]u8 = undefined;
        var buf_ring = try std.os.linux.IoUring.BufferGroup.init(&self.ring, 0, &mega_buffer, HDR_BUFSZ * NUM_BUFFERS, NUM_BUFFERS);
        defer buf_ring.deinit();

        var cqes: [CQES]std.os.linux.io_uring_cqe = undefined;
        _ = try buf_ring.recv_multishot(0, self.socket, 0);
        _ = try self.ring.submit();

        while (true) {
            const count = try self.ring.copy_cqes(&cqes, 1);

            for (cqes[0..count]) |*cqe| {
                if (cqe.res < 0) {
                    // Check if it's the end of multishot
                    if (cqe.flags & std.os.linux.IORING_CQE_F_MORE == 0) {
                        std.debug.print("Multishot receive ended, resubmitting...\n", .{});

                        // Resubmit multishot receive
                        _ = try buf_ring.recv_multishot(0, self.socket, 0);
                        _ = try self.ring.submit();
                        continue;
                    }

                    std.debug.print("Error: {}\n", .{cqe.res});
                    continue;
                }

                const buffer_id = try cqe.buffer_id();
                const bytes_read = @as(usize, @intCast(cqe.res));

                // std.debug.print("Received {} bytes in buffer {}\n", .{ bytes_read, buffer_id });

                const data = buf_ring.get_cqe(cqe.*) catch unreachable;

                if (bytes_read == 28) {
                    // Parse IP header
                    const ip: *const IpHeader = @ptrCast(@alignCast(data.ptr));
                    
                    const source_ip = ip.getSourceIp();
                    std.log.err("  Source IP: {}.{}.{}.{}", .{ source_ip[0], source_ip[1], source_ip[2], source_ip[3] });
                    
                    // Write to CSV file
                    if (self.csv_file) |file| {
                        const timestamp = std.time.milliTimestamp();
                        const csv_line = try std.fmt.allocPrint(allocator, "{},{}.{}.{}.{}\n", .{
                            timestamp,
                            source_ip[0],
                            source_ip[1], 
                            source_ip[2],
                            source_ip[3]
                        });
                        defer allocator.free(csv_line);
                        file.writeAll(csv_line) catch |err| {
                            std.log.err("Failed to write to CSV: {}", .{err});
                        };
                    }
                }

                // Return buffer to the pool
                buf_ring.put(buffer_id);

                // Check if more completions are coming
                if (cqe.flags & std.os.linux.IORING_CQE_F_MORE == 0) {
                    std.debug.print("No more data in this batch\n", .{});
                }
            }

            // for (cqes[0..n]) |*cqe| {
            //     if (cqe.res > 0) {
            //         // const size: usize = @intCast(cqe.res);

            //         const buf = buf_ring.get_cqe(cqe.*) catch unreachable;
            //         // const hdr = std.mem.bytesAsValue(std.os.linux.io_uring_recvmsg_out, buf[0..]);
            //         // var off = @sizeOf(std.os.linux.io_uring_recvmsg_out) + hdr.namelen + hdr.controllen;
            //         // while (off < size) {
            //         //     if (buf[off + 1] != buf[off] ^ 32) {
            //         //         std.log.err("parity validation failed ({} != {})", .{ buf[off + 1], buf[off] ^ 32 });
            //         //         return error.ValidationFailure;
            //         //     }
            //         //     if (!std.mem.allEqual(u8, buf[off + 2 .. off + BUFSZ], 'P')) {
            //         //         std.log.err("packet validation failed", .{});
            //         //         return error.ValidationFailure;
            //         //     }
            //         //     off += BUFSZ;
            //         // }

            //         if (buf.len == 28) {
            //             // Parse IP header
            //             const ip: *const IpHeader = @ptrCast(@alignCast(buf.ptr));
            //             // Parse ICMP header (starts after IP header)
            //             // const icmp_start = buf[20..];
            //             // const icmp: *const IcmpHeader = @ptrCast(@alignCast(icmp_start.ptr));

            //             // std.debug.print("IP Header:\n", .{});
            //             // std.debug.print("  Version: {}\n", .{ip.getVersion()});
            //             // std.debug.print("  Header Length: {} bytes\n", .{ip.getHeaderLengthBytes()});
            //             // std.debug.print("  Total Length: {}\n", .{ip.getTotalLength()});
            //             // std.debug.print("  Protocol: {} (1 = ICMP)\n", .{ip.protocol});
            //             std.debug.print("  Source IP: {}.{}.{}.{}\n", .{ ip.getSourceIp()[0], ip.getSourceIp()[1], ip.getSourceIp()[2], ip.getSourceIp()[3] });
            //             // std.debug.print("  Dest IP: {}.{}.{}.{}\n", .{ ip.getDestIp()[0], ip.getDestIp()[1], ip.getDestIp()[2], ip.getDestIp()[3] });

            //             // std.debug.print("\nICMP Header:\n", .{});
            //             // std.debug.print("  Type: {} (0 = Echo Reply)\n", .{icmp.type});
            //             // std.debug.print("  Code: {}\n", .{icmp.code});
            //             // std.debug.print("  Checksum: 0x{X}\n", .{icmp.getChecksum()});
            //             // std.debug.print("  ID: {}\n", .{icmp.getId()});
            //             // std.debug.print("  Sequence: {}\n", .{icmp.getSeq()});
            //         }

            //         // const hdr = std.mem.bytesAsValue(std.os.linux.io_uring_recvmsg_out, buf[0..@sizeOf(std.os.linux.io_uring_recvmsg_out)]);

            //         // release buffer
            //         buf_ring.put(cqe.buffer_id() catch unreachable);

            //         // Resubmit receive operation to continue listening
            //         _ = try buf_ring.recv_multishot(0, self.socket, 0);
            //         _ = try self.ring.submit();
            //         // const actual_size = size - @sizeOf(std.os.linux.io_uring_recvmsg_out);
            //         // total_received += actual_size;
            //         // total_packets += actual_size / BUFSZ;
            //     }
            //     // _ = try buf_ring.recv_multishot(0, self.socket, 0);
            //     // _ = try self.ring.submit();
            // }
        }
    }
};
