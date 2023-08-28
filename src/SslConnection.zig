const std = @import("std");
const c = @import("c.zig");

const codes = @import("wolfssl-codes.zig");

const SslConnection = @This();

ssl: *c.WOLFSSL,
stream: std.net.Stream,

pub const ReadError = std.net.Stream.ReadError;
pub const WriteError = std.net.Stream.WriteError;
pub const Reader = std.io.Reader(*SslConnection, ReadError, read);
pub const Writer = std.io.Writer(*SslConnection, WriteError, read);

pub fn close(self: *SslConnection) void {
    _ = c.wolfSSL_free(self.ssl);
    self.stream.close();
    self.* = undefined;
}

pub fn reader(self: *SslConnection) Reader {
    return .{ .context = self };
}

pub fn writer(self: *SslConnection) Writer {
    return .{ .context = self };
}

pub fn read(self: *SslConnection, buffer: []u8) !usize {
    const len = c.wolfSSL_read(self.ssl, buffer.ptr, @as(c_int, @intCast(buffer.len)));
    if (len < 0) {
        try codes.retCheck(c.wolfSSL_get_error(self.ssl, len));
    }
    return @intCast(len);
}

pub fn write(self: *SslConnection, buffer: []const u8) !usize {
    const len = c.wolfSSL_write(self.ssl, buffer.ptr, @as(c_int, @intCast(buffer.len)));
    if (len < 0) {
        try codes.retCheck(c.wolfSSL_get_error(self.ssl, len));
    }
    return @intCast(len);
}
