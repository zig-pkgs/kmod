// file: pkcs7/module_parser.zig
const std = @import("std");
const pkcs7 = @import("pkcs7.zig");

const Allocator = std.mem.Allocator;

pub const ModuleParseError = error{
    SignatureNotFound,
    InvalidSignatureFormat,
    ModuleTooSmall,
};

const MAGIC_STRING = "~Module signature appended~\n";

// Corresponds to 'struct module_signature' in the Linux kernel.
// We align it to ensure correct packing and access to sig_len.
const ModuleSignature = extern struct {
    algo: u8,
    hash: u8,
    id_type: u8,
    signer_len: u8,
    key_id_len: u8,
    __pad: [3]u8,
    sig_len: u32, // The length of the signature data that follows

    pub fn fromRaw(bytes: []const u8) *align(1) const ModuleSignature {
        return std.mem.bytesAsValue(ModuleSignature, bytes);
    }

    pub fn sigLength(self: ModuleSignature) usize {
        return @intCast(std.mem.bigToNative(u32, self.sig_len));
    }
};

pub const ParseResult = struct {
    header: *align(1) const ModuleSignature,
    body: []const u8,
    without_magic: []const u8,
};

/// Searches a kernel module's byte data from the end to find and extract
/// the raw PKCS#7 signature blob. This implementation correctly handles
/// the on-disk format where the magic string is at the very end of the file.
///
/// This function is zero-copy and returns a slice pointing into the original
/// `module_data` buffer.
pub fn extractPkcs7FromModule(module_data: []const u8) !ParseResult {
    // 1. The magic string must be at the very end of the file.
    if (!std.mem.endsWith(u8, module_data, MAGIC_STRING)) {
        return ModuleParseError.SignatureNotFound;
    }

    // 2. Temporarily slice off the magic string to work with the preceding data.
    const data_before_magic = module_data[0 .. module_data.len - MAGIC_STRING.len];

    // 3. The `ModuleSignature` struct must be at the end of this new slice.
    //    Ensure there's enough data to even hold the struct.
    if (data_before_magic.len < @sizeOf(ModuleSignature)) {
        return ModuleParseError.InvalidSignatureFormat;
    }

    // 4. Read the struct from the end of the slice.
    //    `bytesAsValue` is a safe, endian-aware way to do this without memcpy.
    const struct_bytes = data_before_magic[data_before_magic.len - @sizeOf(ModuleSignature) ..];
    const sig_info = ModuleSignature.fromRaw(struct_bytes);

    // 5. The PKCS#7 data comes just before the struct. Calculate its boundaries.
    const data_before_struct = data_before_magic[0 .. data_before_magic.len - @sizeOf(ModuleSignature)];

    const pkcs7_len = sig_info.sigLength();

    if (data_before_struct.len < pkcs7_len) {
        return ModuleParseError.InvalidSignatureFormat;
    }

    const pkcs7_start = data_before_struct.len - pkcs7_len;
    return .{
        .header = sig_info,
        .body = data_before_struct[pkcs7_start..],
        .without_magic = data_before_magic,
    };
}
