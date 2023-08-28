const std = @import("std");
const c = @import("c.zig");

const SslConnection = @import("SslConnection.zig");
const codes = @import("wolfssl-codes.zig");
const Context = @This();

ctx: *c.WOLFSSL_CTX = undefined,

pub const ContextErrors = error{ContextInitError};

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

pub fn init(method: Methods) !Context {
    var self: Context = .{};
    self.ctx = c.wolfSSL_CTX_new(method.getMethod()) orelse
        return ContextErrors.ContextInitError;

    c.wolfSSL_CTX_SetIORecv(self.ctx, CtxIORecv);
    c.wolfSSL_CTX_SetIOSend(self.ctx, CtxIOSend);

    return self;
}

pub fn deinit(self: *Context) void {
    _ = c.wolfSSL_CTX_free(self.ctx);
    self.* = undefined;
}

pub fn useCertificateAuthority(self: *Context, path: [:0]const u8) !void {
    try codes.retCheck(c.wolfSSL_CTX_load_verify_locations(
        self.ctx,
        path.ptr,
        0,
    ));
}

pub fn useCertificate(self: *Context, path: [:0]const u8) !void {
    try codes.retCheck(c.wolfSSL_CTX_use_certificate_file(
        self.ctx,
        path.ptr,
        c.SSL_FILETYPE_PEM,
    ));
}

pub fn usePrivateKey(self: *Context, path: [:0]const u8) !void {
    try codes.retCheck(c.wolfSSL_CTX_use_PrivateKey_file(
        self.ctx,
        path.ptr,
        c.SSL_FILETYPE_PEM,
    ));
}

pub fn newSslConnection(self: *Context, stream: std.net.Stream) SslConnection {
    var ssl = c.wolfSSL_new(self.ctx).?;
    var conn: SslConnection = .{ .ssl = ssl, .stream = stream };

    // set the io contexts
    c.wolfSSL_SetIOReadCtx(ssl, &conn.stream);
    c.wolfSSL_SetIOWriteCtx(ssl, &conn.stream);

    // c.wolfSSL_set_verify(ssl, c.SSL_VERIFY_PEER, VerifyPeer);
    return conn;
}

fn VerifyPeer(
    _: c_int,
    certificate_store_ctx: [*c]c.WOLFSSL_X509_STORE_CTX,
) callconv(.C) c_int {
    _ = certificate_store_ctx;
    // TODO: always verify
    return c.SSL_SUCCESS;
}

fn CtxIORecv(
    ssl: ?*c.WOLFSSL,
    buf: [*c]u8,
    len: c_int,
    ctx: ?*anyopaque,
) callconv(.C) c_int {
    _ = ssl;
    if (len == 0) return 0;

    const stream: *std.net.Stream = @ptrCast(@alignCast(ctx.?));
    const read_len = stream.read(buf[0..@intCast(len)]) catch |err| {
        std.debug.print("RECV ERR: {}\n", .{err});
        return codes.readErrorToWolfSslError(err);
    };

    if (read_len == 0)
        return @intFromEnum(codes.WolfSslStatusCodes.WOLFSSL_CBIO_ERR_CONN_CLOSE);
    return @intCast(read_len);
}

fn CtxIOSend(
    ssl: ?*c.WOLFSSL,
    buf: [*c]u8,
    len: c_int,
    ctx: ?*anyopaque,
) callconv(.C) c_int {
    _ = ssl;
    if (len == 0) return 0;

    const stream: *std.net.Stream = @ptrCast(@alignCast(ctx.?));
    const write_len = stream.write(buf[0..@intCast(len)]) catch |err| {
        std.debug.print("SEND ERR: {}\n", .{err});
        return codes.writeErrorToWolfSslError(err);
    };

    if (write_len == 0)
        return @intFromEnum(codes.WolfSslStatusCodes.WOLFSSL_CBIO_ERR_CONN_CLOSE);
    return @intCast(write_len);
}
