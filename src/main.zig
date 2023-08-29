const std = @import("std");

// expose c api
pub const c = @import("c.zig");
pub const status = @import("status.zig");

pub fn init() !void {
    try status.check(c.wolfSSL_Init());
}

pub fn deinit() void {
    _ = c.wolfSSL_Cleanup();
}

pub const Ssl = struct {
    pub const ReadError = status.ReadError;
    pub const WriteError = status.WriteError;

    pub const Reader = std.io.Reader(*Ssl, ReadError, read);
    pub const Writer = std.io.Reader(*Ssl, WriteError, write);

    ssl: *c.WOLFSSL,

    pub fn init(ctx: *Context, stream: *std.net.Stream) Ssl {
        var ssl = c.wolfSSL_new(ctx.ctx).?;

        // set IO contexts
        c.wolfSSL_SetIOReadCtx(ssl, stream);
        c.wolfSSL_SetIOWriteCtx(ssl, stream);

        return .{ .ssl = ssl };
    }

    pub fn deinit(self: *Ssl) void {
        _ = c.wolfSSL_free(self.ssl);
        self.* = undefined;
    }

    pub fn reader(self: *Ssl) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: *Ssl) Writer {
        return .{ .context = self };
    }

    pub fn read(self: *Ssl, buffer: []u8) ReadError!usize {
        const len: c_int = @intCast(buffer.len);
        const read_bytes = c.wolfSSL_read(self.ssl, buffer.ptr, len);
        if (read_bytes < 0) {
            const err = c.wolfSSL_get_error(self.ssl, read_bytes);
            return status.asReadError(err) orelse {
                return ReadError.InputOutput;
            };
        }
        return @intCast(read_bytes);
    }

    pub fn write(self: *Ssl, buffer: []const u8) WriteError!usize {
        const len: c_int = @intCast(buffer.len);
        const write_bytes = c.wolfSSL_write(self.ssl, buffer.ptr, len);
        if (write_bytes < 0) {
            const err = c.wolfSSL_get_error(self.ssl, write_bytes);
            return status.asWriteError(err) orelse {
                return WriteError.InputOutput;
            };
        }
        return @intCast(write_bytes);
    }
};

pub const Context = struct {
    pub const Methods = enum {
        TLSv1_3_Server,
        TLSv1_3_Client,
        TLSv1_2_Server,
        TLSv1_2_Client,

        pub fn getMethod(self: Methods) ?*c.WOLFSSL_METHOD {
            return switch (self) {
                .TLSv1_3_Server => c.wolfTLSv1_3_server_method(),
                .TLSv1_3_Client => c.wolfTLSv1_3_client_method(),
                .TLSv1_2_Server => c.wolfTLSv1_2_server_method(),
                .TLSv1_2_Client => c.wolfTLSv1_2_client_method(),
            };
        }
    };

    ctx: *c.WOLFSSL_CTX,

    pub fn init(method: Methods) !Context {
        var ctx = c.wolfSSL_CTX_new(method.getMethod()) orelse
            return status.WolfSslErrors.WolfSSLError;

        // configure IO hooks
        c.wolfSSL_CTX_SetIORecv(ctx, ctxIORecv);
        c.wolfSSL_CTX_SetIOSend(ctx, ctxIOSend);

        return .{ .ctx = ctx };
    }

    pub fn deinit(self: *Context) void {
        _ = c.wolfSSL_CTX_free(self.ctx);
        self.* = undefined;
    }

    pub fn usePrivateKey(self: *Context, path: [:0]const u8) !void {
        const ret = c.wolfSSL_CTX_use_PrivateKey_file(
            self.ctx,
            path.ptr,
            c.SSL_FILETYPE_PEM,
        );
        try status.check(ret);
    }

    pub fn useCertificate(self: *Context, path: [:0]const u8) !void {
        const ret = c.wolfSSL_CTX_use_certificate_file(
            self.ctx,
            path.ptr,
            c.SSL_FILETYPE_PEM,
        );
        try status.check(ret);
    }

    fn ctxIORecv(
        _: ?*c.WOLFSSL,
        buf: [*c]u8,
        len: c_int,
        ctx: ?*anyopaque,
    ) callconv(.C) c_int {
        if (len == 0) return 0;

        const stream: *std.net.Stream = @ptrCast(@alignCast(ctx.?));
        const read_len = stream.read(buf[0..@intCast(len)]) catch |err| {
            std.debug.print("RECV ERR: {}\n", .{err});
            return status.readErr(err);
        };

        if (read_len == 0)
            return @intFromEnum(status.WolfSslStatusCodes.WOLFSSL_CBIO_ERR_CONN_CLOSE);
        return @intCast(read_len);
    }

    fn ctxIOSend(
        _: ?*c.WOLFSSL,
        buf: [*c]u8,
        len: c_int,
        ctx: ?*anyopaque,
    ) callconv(.C) c_int {
        if (len == 0) return 0;

        const stream: *std.net.Stream = @ptrCast(@alignCast(ctx.?));
        const write_len = stream.write(buf[0..@intCast(len)]) catch |err| {
            std.debug.print("SEND ERR: {}\n", .{err});
            return status.writeErr(err);
        };

        if (write_len == 0)
            return @intFromEnum(status.WolfSslStatusCodes.WOLFSSL_CBIO_ERR_CONN_CLOSE);
        return @intCast(write_len);
    }
};
