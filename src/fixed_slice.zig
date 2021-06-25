const std = @import("std");
const mem = std.mem;

pub fn FixedSlice(comptime T: type, comptime max_len: usize) type {
    return struct {
        const Self = @This();
        buffer: [max_len]T,
        len: usize = 0,

        pub fn init(len: usize) !Self {
            if (len > max_len) return error.SliceTooBig;
            var buffer: [max_len]T = undefined;
            return Self{ .buffer = buffer, .len = len };
        }

        pub fn slice(self: *Self) []T {
            return self.buffer[0..self.len];
        }

        pub fn constSlice(self: Self) []const T {
            return self.buffer[0..self.len];
        }

        pub fn resize(self: *Self, len: usize) ![]T {
            if (len > max_len) return error.SliceTooBig;
            self.len = len;
            return self.slice();
        }

        pub fn fromSlice(m: []const T) !Self {
            var fixed_slice = try init(m.len);
            mem.copy(T, fixed_slice.slice(), m);
            return fixed_slice;
        }

        pub fn clone(self: Self) Self {
            return fromSlice(self.constSlice()) catch unreachable;
        }
    };
}
