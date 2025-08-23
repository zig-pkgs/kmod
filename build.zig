const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const t = target.result;

    const kmod_dep = b.dependency("kmod", .{});

    const config_h = b.addConfigHeader(
        .{
            .style = .{ .cmake = b.path("src/config.h.in") },
            .include_path = "config.h",
        },
        .{
            .DISTCONFDIR = "/usr/lib",
            .ENABLE_DEBUG = false,
            .ENABLE_ELFDBG = false,
            .ENABLE_LOGGING = true,
            .ENABLE_OPENSSL = false,
            .ENABLE_XZ = true,
            .ENABLE_XZ_DLOPEN = false,
            .ENABLE_ZLIB = true,
            .ENABLE_ZLIB_DLOPEN = false,
            .ENABLE_ZSTD = true,
            .ENABLE_ZSTD_DLOPEN = false,
            .HAVE_DECL_BASENAME = @intFromBool(t.isGnuLibC()),
            .HAVE_DECL___XSTAT = 0,
            .HAVE_FOPEN64 = null,
            .HAVE_NORETURN = null,
            .HAVE_OPEN64 = null,
            .HAVE_SECURE_GETENV = null,
            .HAVE_STAT64 = null,
            .HAVE_STATIC_ASSERT = null,
            .HAVE_STRUCT_STAT_ST_MTIM = null,
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

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate_c.addConfigHeader(config_h);
    translate_c.addIncludePath(kmod_dep.path("."));
    translate_c.addIncludePath(kmod_dep.path("libkmod"));

    const c_mod = translate_c.createModule();

    const core_lib = b.addLibrary(.{
        .name = "kmod-core",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/kmod_core.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "c", .module = c_mod },
            },
        }),
    });

    const lib_mod = b.addModule("kmod", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "c", .module = c_mod },
        },
    });
    lib_mod.addIncludePath(kmod_dep.path("."));
    lib_mod.addIncludePath(kmod_dep.path("shared"));
    lib_mod.addIncludePath(kmod_dep.path("libkmod"));

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "kmod",
        .root_module = lib_mod,
    });
    lib.linkLibrary(core_lib);
    lib.addConfigHeader(config_h);
    lib.addCSourceFiles(.{
        .root = kmod_dep.path("."),
        .files = &libshared_src,
        .flags = &.{"-includeconfig.h"},
    });
    lib.addCSourceFiles(.{
        .root = kmod_dep.path("."),
        .files = &libkmod_src,
        .flags = &.{"-includeconfig.h"},
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
