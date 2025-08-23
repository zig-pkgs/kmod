const std = @import("std");
const c = @import("c");
const mem = std.mem;
const posix = std.posix;
const compress = std.compress;
const assert = std.debug.assert;
const signature = @import("signature.zig");
const testing = std.testing;

const max_module_size = 32 * 1024 * 1024;
const gpa = std.heap.c_allocator;

comptime {
    @export(&signature.kmod_module_signature_info, .{
        .name = "kmod_module_signature_info",
    });
    @export(&signature.kmod_module_signature_info_free, .{
        .name = "kmod_module_signature_info_free",
    });
}

fn uncompressXz(file: std.fs.File) ![]u8 {
    var read_buffer: [8 * 1024]u8 = undefined;
    var file_reader = file.reader(&read_buffer);
    var reader = &file_reader.interface;
    var d = try compress.xz.decompress(gpa, reader.adaptToOldInterface());
    defer d.deinit();
    var buf: std.array_list.Managed(u8) = .init(gpa);
    defer buf.deinit();
    try d.reader().readAllArrayList(&buf, max_module_size);
    return try buf.toOwnedSlice();
}

export fn kmod_file_load_xz(file: [*c]c.kmod_file) c_int {
    const f: std.fs.File = .{ .handle = file.*.fd };
    const buf = uncompressXz(f) catch return -1;
    file.*.memory = buf.ptr;
    file.*.size = @intCast(buf.len);
    return 0;
}

fn uncompressGz(file: std.fs.File) ![]u8 {
    var read_buffer: [8 * 1024]u8 = undefined;
    var file_reader = file.reader(&read_buffer);
    const reader = &file_reader.interface;
    var flate_buffer: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(reader, .gzip, &flate_buffer);
    return try decompress.reader.allocRemaining(gpa, .unlimited);
}

export fn kmod_file_load_zlib(file: [*c]c.kmod_file) c_int {
    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();

    const f: std.fs.File = .{ .handle = file.*.fd };
    const buf = uncompressGz(f) catch return -1;
    file.*.memory = buf.ptr;
    file.*.size = @intCast(buf.len);
    return 0;
}

fn uncompressZstd(file: std.fs.File) ![]u8 {
    var read_buffer: [8 * 1024]u8 = undefined;
    var file_reader = file.reader(&read_buffer);
    const reader = &file_reader.interface;
    const window_len = std.compress.zstd.default_window_len;
    const window_buffer = try gpa.alloc(u8, window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window_buffer);
    var decompress: std.compress.zstd.Decompress = .init(reader, window_buffer, .{
        .verify_checksum = false,
        .window_len = window_len,
    });
    return try decompress.reader.allocRemaining(gpa, .unlimited);
}

export fn kmod_file_load_zstd(file: [*c]c.kmod_file) c_int {
    const f: std.fs.File = .{ .handle = file.*.fd };
    const buf = uncompressZstd(f) catch return -1;
    file.*.memory = buf.ptr;
    file.*.size = @intCast(buf.len);
    return 0;
}
