const std = @import("std");
const testing = std.testing;

pub const c = @import("c.zig");
const retCheck = @import("wolfssl-codes.zig").retCheck;

pub const Context = @import("Context.zig");

pub fn init() !void {
    try retCheck(c.wolfSSL_Init());
}

pub fn deinit() void {
    _ = c.wolfSSL_Cleanup();
}

test "basic functionality" {
    try init();
    defer deinit();
}
