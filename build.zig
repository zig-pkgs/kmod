const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const kmod_dep = b.dependency("kmod", .{});

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate_c.addIncludePath(kmod_dep.path("."));
    translate_c.addIncludePath(kmod_dep.path("libkmod"));

    const t = target.result;

    const config_h = b.addConfigHeader(
        .{ .style = .blank },
        .{
            .DISTCONFDIR = "/usr/lib",
            .ENABLE_DEBUG = 0,
            .ENABLE_ELFDBG = 0,
            .ENABLE_LOGGING = 1,
            .ENABLE_XZ = 1,
            .ENABLE_XZ_DLOPEN = 0,
            .ENABLE_ZLIB = 1,
            .ENABLE_ZLIB_DLOPEN = 0,
            .ENABLE_ZSTD = 1,
            .ENABLE_ZSTD_DLOPEN = 0,
            .HAVE_DECL_BASENAME = @intFromBool(t.isGnuLibC()),
            .HAVE_DECL___XSTAT = 0,
            .HAVE_FOPEN64 = "",
            .HAVE_NORETURN = "",
            .HAVE_OPEN64 = "",
            .HAVE_SECURE_GETENV = "",
            .HAVE_STAT64 = "",
            .HAVE_STATIC_ASSERT = "",
            .HAVE_STRUCT_STAT_ST_MTIM = "",
            .HAVE___BUILTIN_CLZ = 1,
            .HAVE___BUILTIN_TYPES_COMPATIBLE_P = 1,
            .HAVE___BUILTIN_UADDLL_OVERFLOW = 1,
            .HAVE___BUILTIN_UADDL_OVERFLOW = 1,
            .HAVE___BUILTIN_UADD_OVERFLOW = 1,
            .HAVE___BUILTIN_UMULLL_OVERFLOW = 1,
            .HAVE___BUILTIN_UMULL_OVERFLOW = 1,
            .HAVE___BUILTIN_UMUL_OVERFLOW = 1,
            .KMOD_FEATURES = "+ZSTD +XZ +ZLIB",
            .MODULE_DIRECTORY = "/lib/modules",
            .PACKAGE = "kmod",
            .SYSCONFDIR = "/etc",
            .VERSION = "34",
            ._GNU_SOURCE = 1,
        },
    );
    var it = config_h.values.iterator();

    const lib_mod = b.addModule("kmod", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lib_mod.addImport("c", translate_c.createModule());
    while (it.next()) |entry| {
        const value: ?[]const u8 = switch (entry.value_ptr.*) {
            .int => |v| b.fmt("{d}", .{v}),
            .string => |v| b.fmt("\"{s}\"", .{v}),
            else => null,
        };
        if (value) |v| lib_mod.addCMacro(entry.key_ptr.*, v);
    }
    lib_mod.addIncludePath(kmod_dep.path("."));
    lib_mod.addIncludePath(kmod_dep.path("shared"));
    lib_mod.addIncludePath(kmod_dep.path("libkmod"));

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "kmod",
        .root_module = lib_mod,
    });
    lib.addConfigHeader(config_h);
    lib.addCSourceFiles(.{
        .root = kmod_dep.path("."),
        .files = &libshared_src,
        .flags = &.{},
    });
    lib.addCSourceFiles(.{
        .root = kmod_dep.path("."),
        .files = &libkmod_src,
        .flags = &.{},
    });
    lib.installHeader(
        kmod_dep.path("libkmod/libkmod.h"),
        "libkmod/libkmod.h",
    );
    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}

const libshared_src = [_][]const u8{
    "shared/array.c",
    "shared/hash.c",
    "shared/strbuf.c",
    "shared/util.c",
};

const libkmod_src = [_][]const u8{
    "libkmod/libkmod-builtin.c",
    "libkmod/libkmod.c",
    "libkmod/libkmod-config.c",
    "libkmod/libkmod-elf.c",
    "libkmod/libkmod-file.c",
    "libkmod/libkmod-index.c",
    "libkmod/libkmod-list.c",
    "libkmod/libkmod-module.c",
};
