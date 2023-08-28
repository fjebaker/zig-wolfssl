const std = @import("std");
const ssl = @import("zigwolfssl");

pub fn main() !void {
    try ssl.init();
    defer ssl.deinit();

    var context = try ssl.Context.init(.TLSv1_2_Client);
    defer context.deinit();

    try context.useCertificateAuthority("./certs/ca-certificate.pem");

    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8044);

    const stream = try std.net.tcpConnectToAddress(address);
    var conn = context.newSslConnection(stream);
    defer conn.close();

    _ = try conn.write("Hello World!");
}
