const std = @import("std");
const icmp = @import("icmp_header.zig");
const ip = @import("ip.zig");

pub const IcmpSocket = struct {
    socket: i32 = 0,

    pub fn init(receiveTimeout: i32) !IcmpSocket {
        const socket = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.RAW,
            std.posix.IPPROTO.ICMP,
        );
        errdefer std.posix.close(socket);

        const tv: std.posix.timeval = .{
            .sec = receiveTimeout,
            .usec = 0,
        };
        try std.posix.setsockopt(
            socket,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&tv),
        );

        return IcmpSocket{ .socket = socket };
    }

    pub fn sendTo(self: *const IcmpSocket, header: icmp.IcmpHeader, address: ip.Ip) !void {
        while (true) {
            _ = std.posix.sendto(
                self.socket,
                @as(*const [8]u8, @ptrCast(&header)),
                0,
                &address.address.any,
                address.address.getOsSockLen(),
            ) catch |err| {
                if (err == error.SystemResources) {
                    // std.debug.print("System overloaded, waiting...\n", .{});
                    std.Thread.sleep(100_000);
                    continue;
                }
                return err;
            };
            break;
        }
    }

    pub fn recv(self: *const IcmpSocket) ?[28]u8 {
        var buffer: [28]u8 = undefined;
        _ = std.posix.recv(self.socket, &buffer, 0) catch |err| {
            if (err == std.posix.RecvFromError.WouldBlock) {
                std.debug.print("recv timeout\n", .{});
            }
            return null;
        };
        // std.debug.print("recv received {d} bytes\n", .{result});
        return buffer;
    }
};
