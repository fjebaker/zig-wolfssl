const std = @import("std");
const ssl = @import("zigwolfssl");

const Server = struct {
    context: *ssl.Context,
    stream_server: std.net.StreamServer,

    pub fn init(ctx: *ssl.Context, opts: std.net.StreamServer.Options) Server {
        return .{
            .context = ctx,
            .stream_server = std.net.StreamServer.init(opts),
        };
    }

    pub fn deinit(self: *Server) void {
        self.stream_server.close();
        self.stream_server.deinit();
        self.* = undefined;
    }

    pub fn listen(self: *Server, addr: std.net.Address) !void {
        try self.stream_server.listen(addr);
    }

    pub fn accept(self: *Server) !std.net.StreamServer.Connection {
        return self.stream_server.accept();
    }
};

pub fn main() !void {
    try ssl.init();
    defer ssl.deinit();

    var context = try ssl.Context.init(.TLSv1_3_Server);
    defer context.deinit();

    // try context.useCertificateAuthority("./certs/ca-certificate.pem");
    // try context.usePrivateKey("./certs/server-private-key.pem");
    // try context.useCertificate("./certs/server-certificate.pem");
    try context.usePrivateKey("./lh-key.rsa");
    try context.useCertificate("./lh-cert.pem");

    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8044);

    var server = Server.init(&context, .{ .reuse_address = true });
    defer server.deinit();

    try server.listen(address);

    const net_conn = try server.accept();
    var conn = server.context.newSslConnection(net_conn.stream);
    defer conn.close();

    var buf: [2048]u8 = undefined;
    const msg_size = try conn.read(buf[0..]);

    std.debug.print("R: {d} {s}\n", .{ msg_size, buf[0..msg_size] });

    // var server = std.net.StreamServer.init(.{ .reuse_address = true });
    // defer server.deinit();

    // try server.listen(address);

    // const conn = try server.accept();
    // defer conn.stream.close();

    // var buf: [1024]u8 = undefined;
    // const msg_size = try conn.stream.read(buf[0..]);

    // _ = try conn.stream.write("Thanks!");
}
