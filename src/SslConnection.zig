const std = @import("std");
const c = @import("c.zig");

const codes = @import("wolfssl-codes.zig");

const SslConnection = @This();

ssl: *c.WOLFSSL,
stream: std.net.Stream,

pub const ReadError = std.net.Stream.ReadError;
pub const WriteError = std.net.Stream.WriteError;
pub const Reader = std.io.Reader(*SslConnection, ReadError, _reader);
pub const Writer = std.io.Writer(*SslConnection, WriteError, _writer);

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

fn _reader(self: *SslConnection, buffer: []u8) ReadError!usize {
    return self.read(buffer) catch |err| {
        inline for (@typeInfo(ReadError).ErrorSet.?) |e| {
            const _err = @field(ReadError, e.name);
            if (err == _err) return _err;
        }
        return ReadError.InputOutput;
    };
}

fn _writer(self: *SslConnection, buffer: []u8) ReadError!usize {
    return self.write(buffer) catch |err| {
        inline for (@typeInfo(WriteError).ErrorSet.?) |e| {
            const _err = @field(WriteError, e.name);
            if (err == _err) return _err;
        }
        return WriteError.InputOutput;
    };
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
