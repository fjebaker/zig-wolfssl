const std = @import("std");
const testing = std.testing;

pub const c = @import("c.zig");
pub const codes = @import("wolfssl-codes.zig");
pub const Context = @import("Context.zig");
pub const SslConnection = @import("SslConnection.zig");

pub fn init() !void {
    try codes.retCheck(c.wolfSSL_Init());
}

pub fn deinit() void {
    _ = c.wolfSSL_Cleanup();
}

test "basic functionality" {
    try init();
    defer deinit();
}
