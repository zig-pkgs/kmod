const std = @import("std");
const c = @import("c");
const mem = std.mem;
const posix = std.posix;
const compress = std.compress;
const assert = std.debug.assert;
const signature = @import("signature.zig");
const builtin = @import("builtin");
const native_arch = builtin.cpu.arch;
const testing = std.testing;

const max_module_size = 32 * 1024 * 1024;
const gpa = std.heap.c_allocator;

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

        /// Flags to control the behavior of a kernel module probe operation.
        /// This is a packed struct that maps directly to the C kmod_probe bitmask.
        pub const ProbeFlags = packed struct(c_uint) {
            /// Corresponds to KMOD_PROBE_FORCE_VERMAGIC (0x00001)
            force_vermagic: bool = false, // bit 0
            /// Corresponds to KMOD_PROBE_FORCE_MODVERSION (0x00002)
            force_modversion: bool = false, // bit 1
            /// Corresponds to KMOD_PROBE_IGNORE_COMMAND (0x00004)
            ignore_command: bool = false, // bit 2
            /// Corresponds to KMOD_PROBE_IGNORE_LOADED (0x00008)
            ignore_loaded: bool = false, // bit 3
            /// Corresponds to KMOD_PROBE_DRY_RUN (0x00010)
            dry_run: bool = false, // bit 4
            /// Corresponds to KMOD_PROBE_FAIL_ON_LOADED (0x00020)
            fail_on_loaded: bool = false, // bit 5

            /// Padding for unused bits 6 through 15.
            _padding1: u10 = 0,

            /// Corresponds to KMOD_PROBE_APPLY_BLACKLIST_ALL (0x10000)
            apply_blacklist_all: bool = false, // bit 16
            /// Corresponds to KMOD_PROBE_APPLY_BLACKLIST (0x20000)
            apply_blacklist: bool = false, // bit 17
            /// Corresponds to KMOD_PROBE_APPLY_BLACKLIST_ALIAS_ONLY (0x40000)
            apply_blacklist_alias_only: bool = false, // bit 18

            /// Padding for the remaining unused bits to fill a 32-bit integer.
            _padding2: u13 = 0,

            // Compile-time check to ensure the struct size is correct.
            comptime {
                std.debug.assert(@sizeOf(ProbeFlags) == @sizeOf(c_uint));
            }
        };

        pub fn insert(self: *const Module, flags: ProbeFlags) !void {
            const rc = c.kmod_module_probe_insert_module(
                self.mod,
                @bitCast(flags),
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

        /// aliased from std.os.linux.O (O.TRUNC and O.NONBLOCK).
        pub const RemoveFlags = switch (native_arch) {
            .x86_64, .aarch64 => packed struct(c_uint) {
                /// Corresponds to KMOD_REMOVE_NOLOG (1)
                no_log: bool = false, // bit 0

                /// Padding for unused bits 1 through 8.
                _padding1: u8 = 0,

                /// Corresponds to KMOD_REMOVE_FORCE (O.TRUNC = 512)
                force: bool = false, // bit 9

                /// Padding for unused bit 10.
                _padding2: u1 = 0,

                /// Corresponds to KMOD_REMOVE_NOWAIT (O.NONBLOCK = 2048)
                no_wait: bool = false, // bit 11

                /// Padding for the remaining unused bits to fill a 32-bit integer.
                _padding3: u20 = 0,

                // Compile-time check to ensure the struct size is correct.
                comptime {
                    std.debug.assert(@sizeOf(RemoveFlags) == @sizeOf(c_uint));
                }
            },
            else => @compileError("missing RemoveFlags constants for this architecture"),
        };

        pub fn remove(self: *const Module, flags: RemoveFlags) !void {
            const rc = c.kmod_module_remove_module(self.mod, @bitCast(flags));
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
