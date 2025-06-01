const std = @import("std");

pub fn getSeed() u64 {
    var seed: u64 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&seed));
    return seed;
}

pub const FeistelPermutation = struct {
    a: u64,
    b: u64,
    seed: u64,
    rounds: u8,
    range: u64,

    pub fn init(rounds: u8, range: u64, seed: u64) FeistelPermutation {
        const rangeSqrt = @sqrt(@as(f64, @floatFromInt(range)));

        const a = @as(u64, @intFromFloat(rangeSqrt - 2));
        var b = @as(u64, @intFromFloat(rangeSqrt + 3));

        while (a * b <= range) {
            b += 1;
        }

        return FeistelPermutation{
            .a = a,
            .b = b,
            .seed = seed,
            .rounds = rounds,
            .range = range,
        };
    }

    fn read(self: *const FeistelPermutation, r: u64, R: u64) u64 {
        var input: [32]u8 = undefined;
        var output: [32]u8 = undefined;

        // Prepare input data: R XOR (seed rotated by r)
        const rotated_seed = (self.seed << @as(u6, @intCast(r & 0x3F))) | (self.seed >> @as(u6, @intCast(64 - (r & 0x3F))));
        const xored = R ^ rotated_seed;

        // Convert to bytes for hashing
        std.mem.writeInt(u64, input[0..8], xored, .little);
        std.mem.writeInt(u64, input[8..16], self.seed, .little);
        std.mem.writeInt(u64, input[16..24], r, .little);

        // Blake3 hash
        std.crypto.hash.Blake3.hash(input[0..24], &output, .{});

        // Convert first 8 bytes back to u64
        return std.mem.readInt(u64, output[0..8], .little);
    }

    fn encrypt(self: *const FeistelPermutation, m: u64) u64 {
        var L = m % self.a;
        var R = m / self.a;
        var j: u32 = 1;

        while (j <= self.rounds) : (j += 1) {
            const tmp = if (j & 1 != 0)
                (L + self.read(j, R)) % self.a
            else
                (L + self.read(j, R)) % self.b;

            L = R;
            R = tmp;
        }

        return if (self.rounds & 1 != 0)
            self.a * L + R
        else
            self.a * R + L;
    }

    pub fn shuffle(self: *const FeistelPermutation, m: u64) u64 {
        var c = self.encrypt(m);
        while (c >= self.range) {
            c = self.encrypt(c);
        }
        return c;
    }
};

test "permutation uniqueness" {
    const allocator = std.testing.allocator;

    const total: u32 = 1000;
    var seen = std.AutoHashMap(u64, bool).init(allocator);
    defer seen.deinit();

    var feistel = FeistelPermutation.init(4, total, getSeed());

    for (0..total) |i| {
        const p = feistel.shuffle(i);
        try std.testing.expect(p < total and p >= 0);
        try std.testing.expect(!seen.contains(p));
        try seen.put(p, true);
    }
}
