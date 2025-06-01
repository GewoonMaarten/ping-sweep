const std = @import("std");
const icmp = @import("icmp_header.zig");

pub const IcmpSocket = struct {
    socket: i32 = 0,

    pub fn init() !IcmpSocket {
        const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.RAW, std.posix.IPPROTO.ICMP);
        errdefer std.posix.close(socket);
        return IcmpSocket{ .socket = socket };
    }

    pub fn sendTo(self: *const IcmpSocket, header: icmp.IcmpHeader, address: std.net.Address) !void {
        const result = try std.posix.sendto(self.socket, @as(*const [8]u8, @ptrCast(&header)), 0, &address.any, address.getOsSockLen());
        std.debug.print("sendTo sent {d} bytes\n", .{result});
    }

    pub fn recv(self: *const IcmpSocket) 28[u8] {
        var buffer: 28[u8] = undefined;
        const result = try std.posix.recv(self.socket, &buffer, 0);
        std.debug.print("recv received {d} bytes\n", .{result});
        return buffer;
    }
};
