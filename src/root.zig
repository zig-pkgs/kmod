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
    const reader = file.reader();
    var d = try compress.xz.decompress(gpa, reader);
    defer d.deinit();
    var buf = std.ArrayList(u8).init(gpa);
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
    const reader = file.reader();
    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();
    try compress.gzip.decompress(reader, buf.writer());
    return try buf.toOwnedSlice();
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
    const reader = file.reader();
    const window_size = std.compress.zstd.DecompressorOptions.default_window_buffer_len;
    const window_buffer = try gpa.create([window_size]u8);
    var d = compress.zstd.decompressor(reader, .{
        .window_buffer = window_buffer,
    });
    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();
    try d.reader().readAllArrayList(&buf, max_module_size);
    return try buf.toOwnedSlice();
}

export fn kmod_file_load_zstd(file: [*c]c.kmod_file) c_int {
    const f: std.fs.File = .{ .handle = file.*.fd };
    const buf = uncompressZstd(f) catch return -1;
    file.*.memory = buf.ptr;
    file.*.size = @intCast(buf.len);
    return 0;
}

pub const Context = struct {
    ctx: *c.kmod_ctx,
    resources_loaded: bool,

    pub const Module = struct {
        mod: *c.kmod_module,

        pub const Info = struct {
            list: *c.kmod_list,

            pub fn key(self: *const Info) []const u8 {
                const key_cstr = c.kmod_module_info_get_key(self.list);
                assert(key_cstr != null);
                return mem.sliceTo(key_cstr, 0);
            }

            pub fn value(self: *const Info) []const u8 {
                const value_cstr = c.kmod_module_info_get_value(self.list);
                assert(value_cstr != null);
                return mem.sliceTo(value_cstr, 0);
            }

            pub const Iterator = struct {
                list: *c.kmod_list,
                current_node: ?*c.kmod_list = null,

                pub fn init(list: *c.kmod_list) @This() {
                    // The list can be null, which means an empty iterator.
                    return .{
                        .list = list,
                        .current_node = list,
                    };
                }

                pub fn deinit(self: *const @This()) void {
                    _ = c.kmod_module_info_free_list(self.list);
                }

                pub fn next(self: *@This()) ?Info {
                    // Use the current node. If it's null, we're at the end.
                    const node = self.current_node orelse return null;

                    // Advance our state for the *next* call to next().
                    self.current_node = c.kmod_list_next(self.list, node);

                    // Return a temporary Module struct.
                    // The caller does NOT own the underlying module and MUST NOT deinit it.
                    return .{ .list = node };
                }
            };
        };

        pub const Iterator = struct {
            list: *c.kmod_list,
            current_node: ?*c.kmod_list = null,

            pub fn init(list: *c.kmod_list) Iterator {
                // The list can be null, which means an empty iterator.
                return .{
                    .list = list,
                    .current_node = list,
                };
            }

            pub fn deinit(self: *const Iterator) void {
                _ = c.kmod_module_unref_list(self.list);
            }

            pub fn next(self: *Iterator) ?Module {
                // Use the current node. If it's null, we're at the end.
                const node = self.current_node orelse return null;

                // Get the module from the current node. It's a new reference.
                const module_ptr = c.kmod_module_get_module(node) orelse {
                    // Should not happen on a valid list, but good to be safe.
                    self.current_node = null;
                    return null;
                };

                // Advance our state for the *next* call to next().
                self.current_node = c.kmod_list_next(self.list, node);

                // Return a temporary Module struct.
                // The caller does NOT own the underlying module and MUST NOT deinit it.
                return .{ .mod = module_ptr };
            }
        };

        pub fn name(self: *const Module) []const u8 {
            return mem.sliceTo(c.kmod_module_get_name(self.mod), 0);
        }

        pub fn path(self: *const Module) ?[]const u8 {
            const path_maybe = c.kmod_module_get_path(self.mod);
            if (path_maybe != null) return mem.sliceTo(path_maybe, 0);
            return null;
        }

        pub fn dependencies(self: *const Module) ?Iterator {
            const list = c.kmod_module_get_dependencies(self.mod);
            if (list != null) {
                @branchHint(.likely);
                return .init(list);
            }
            return null;
        }

        pub fn info(self: *const Module) !Info.Iterator {
            var list_maybe: ?*c.kmod_list = null;
            if (c.kmod_module_get_info(self.mod, &list_maybe) < 0) {
                @branchHint(.unlikely);
                return error.OutOfMemory;
            }
            if (list_maybe) |list| {
                @branchHint(.likely);
                return .init(list);
            }
            return error.GetInfoFailed;
        }

        pub const InsertOptions = struct {
            // dry run, do not insert module, just call the associated callback function
            dry_run: bool = false,
            // do not check whether the module is already live in the kernel or not
            ignore_loaded: bool = false,
            // probe will fail if `ignore_loaded` is not specified and
            // the module is already live in the kernel
            fail_on_loaded: bool = false,
            // probe will return early with this enum, if the module is blacklisted
            apply_blacklist: bool = true,
        };

        pub fn insert(self: *const Module, options: InsertOptions) !void {
            var flags: c_uint = 0;
            if (options.apply_blacklist) flags |= c.KMOD_PROBE_APPLY_BLACKLIST;
            if (options.fail_on_loaded) flags |= c.KMOD_PROBE_FAIL_ON_LOADED;
            if (options.ignore_loaded) flags |= c.KMOD_PROBE_IGNORE_LOADED;
            if (options.dry_run) flags |= c.KMOD_PROBE_DRY_RUN;
            const rc = c.kmod_module_probe_insert_module(
                self.mod,
                flags,
                null,
                null,
                null,
                null,
            );
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .PERM => return error.PermissionDenied,
                else => |e| return posix.unexpectedErrno(e),
            }
        }

        pub const RemoveOptions = struct {
            force: bool = false,
            no_wait: bool = false,
            no_log: bool = false,
        };

        pub fn remove(self: *const Module, options: RemoveOptions) !void {
            var flags: c_uint = 0;
            if (options.force) flags |= c.KMOD_REMOVE_FORCE;
            if (options.no_log) flags |= c.KMOD_REMOVE_NOLOG;
            if (options.no_wait) flags |= c.KMOD_REMOVE_NOWAIT;
            const rc = c.kmod_module_remove_module(self.mod, flags);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .PERM => return error.PermissionDenied,
                else => |e| return posix.unexpectedErrno(e),
            }
        }

        pub fn deinit(self: *const Module) void {
            _ = c.kmod_module_unref(self.mod);
        }
    };

    pub const InitOptions = struct {
        dirname: [*c]const u8 = null,
        load_resources: bool = false,
    };

    pub fn init(options: InitOptions) !Context {
        var null_config: [*c]const u8 = null;
        const ctx_maybe = c.kmod_new(options.dirname, &null_config);
        if (ctx_maybe) |ctx| {
            @branchHint(.likely);
            var resources_loaded: bool = false;
            if (options.load_resources and c.kmod_load_resources(ctx) == 0) {
                resources_loaded = true;
            }
            return .{
                .ctx = ctx,
                .resources_loaded = resources_loaded,
            };
        }
        return error.CtxInitFailed;
    }

    pub fn deinit(self: *Context) void {
        if (self.resources_loaded) _ = c.kmod_unload_resources(self.ctx);
        _ = c.kmod_unref(self.ctx);
    }

    pub fn lookup(self: *Context, alias: [:0]const u8) !Module.Iterator {
        var list_maybe: ?*c.kmod_list = null;
        if (c.kmod_module_new_from_lookup(self.ctx, alias, &list_maybe) != 0) {
            @branchHint(.unlikely);
            return error.LookupFailed;
        }
        if (list_maybe) |list| {
            @branchHint(.likely);
            return .init(list);
        }
        return error.ModuleNotFound;
    }
};

test {
    var ctx = try Context.init(.{ .load_resources = true });
    defer ctx.deinit();

    var it = try ctx.lookup("amdgpu");
    defer it.deinit();
    while (it.next()) |mod| {
        defer mod.deinit();
        try testing.expect(mod.name().len > 0);
        try testing.expect(mod.path().?.len > 0);
        try mod.insert(.{ .dry_run = true });
        var it_info = try mod.info();
        defer it_info.deinit();
        while (it_info.next()) |info| {
            try testing.expect(info.key().len > 0);
            try testing.expect(info.value().len > 0);
        }
        var dep_it = mod.dependencies() orelse continue;
        while (dep_it.next()) |dep| {
            defer dep.deinit();
            try testing.expect(dep.name().len > 0);
            try testing.expect(dep.path().?.len > 0);
        }
    }
}
