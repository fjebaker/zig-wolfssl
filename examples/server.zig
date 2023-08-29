const std = @import("std");

const zzl = @import("zigwolfssl");

pub fn main() !void {
    try zzl.init();
    defer zzl.deinit();

    var ctx = try zzl.Context.init(.TLSv1_3_Server);
    defer ctx.deinit();

    try ctx.useCertificate("./lh-cert.pem");
    try ctx.usePrivateKey("./lh-key.rsa");

    var server = std.net.StreamServer.init(.{ .reuse_address = true });
    defer server.deinit();

    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8044);
    try server.listen(address);

    std.debug.print("Listening...\n", .{});

    var buffer: [2048]u8 = undefined;
    while (true) {
        var conn = try server.accept();
        defer conn.stream.close();

        std.debug.print("Accepted\n", .{});

        var ssl = zzl.Ssl.init(ctx, conn.stream);
        defer ssl.deinit();

        const r_size = try ssl.read(&buffer);
        std.debug.print("R: {d} : {s}\n", .{ r_size, buffer[0..r_size] });

        const w_size = try ssl.write("Thank you!\n");
        std.debug.print("W: {d}\n", .{w_size});
    }
}
