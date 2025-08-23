/// This is to remove dependency on openssl, currently untested
const std = @import("std");
const c = @import("c");
const pkcs7 = @import("signature/pkcs7.zig");
const module_parser = @import("signature/module_parser.zig");

const gpa = std.heap.c_allocator;

// These maps are from the C source.
const PkeyAlgo = enum { DSA, RSA };
const PkeyHashAlgo = enum {
    md4,
    md5,
    sha1,
    rmd160,
    sha256,
    sha384,
    sha512,
    sha224,
    sm3,
};

const PkeyIdType = enum(u8) {
    PGP,
    X509,
    @"PKCS#7",
};

// This is the C-callable free function.
fn pkcs7_free_c(s: ?*anyopaque) callconv(.C) void {
    const sig_info: [*c]c.kmod_signature_info = @ptrCast(@alignCast(s));
    if (sig_info.*.private) |ptr| {
        var signer_infos: *pkcs7.SignerInfos = @ptrCast(@alignCast(ptr));
        signer_infos.deinit();
        gpa.destroy(ptr);
    }
}

pub fn kmod_module_signature_info(
    file: [*c]const c.kmod_file,
    sig_info: [*c]c.kmod_signature_info,
) callconv(.c) bool {
    const size: usize = @intCast(c.kmod_file_get_size(file));
    const content_ptr: [*]u8 = @ptrCast(@alignCast(c.kmod_file_get_contents(file)));
    const contents = content_ptr[0..size];

    const parsed = module_parser.extractPkcs7FromModule(contents) catch return false;

    const id_type = std.meta.intToEnum(PkeyIdType, parsed.header.id_type) catch return false;
    const pkey_algo = std.meta.intToEnum(PkeyAlgo, parsed.header.algo) catch return false;
    const pkey_hash_algo: PkeyHashAlgo = std.meta.intToEnum(PkeyHashAlgo, parsed.header.hash) catch return false;

    switch (id_type) {
        .@"PKCS#7" => {
            const signer_infos = pkcs7.getSignerInfos(gpa, parsed.body) catch return false;
            const private = gpa.create(@TypeOf(signer_infos)) catch return false;
            sig_info.*.private = private;
            const signer_first = signer_infos.items[0];

            sig_info.*.signer = signer_first.sid.issuer_and_serial_number.issuer_common_name.?.ptr;
            sig_info.*.signer_len = signer_first.sid.issuer_and_serial_number.issuer_common_name.?.len;
            sig_info.*.key_id = signer_first.sid.issuer_and_serial_number.serial_number.ptr;
            sig_info.*.key_id_len = signer_first.sid.issuer_and_serial_number.serial_number.len;
            sig_info.*.sig = signer_first.signature.ptr;
            sig_info.*.sig_len = signer_first.signature.len;
            sig_info.*.hash_algo = signer_first.digest_algorithm.lookup().name;
            sig_info.*.algo = signer_first.signature_algorithm.lookup().name;
        },
        .PGP, .X509 => {
            // This is the `fill_default` case
            const sig_len = parsed.header.sigLength();
            var cursor = sig_len;
            const sig = parsed.without_magic[cursor - sig_len .. cursor];
            sig_info.*.sig = sig.ptr;
            sig_info.*.sig_len = sig.len;
            cursor -= sig_len;
            const key_id = parsed.without_magic[cursor - parsed.header.key_id_len .. cursor];
            sig_info.*.key_id = key_id.ptr;
            sig_info.*.key_id_len = key_id.len;
            cursor -= parsed.header.key_id_len;
            const signer = parsed.without_magic[cursor - parsed.header.signer_len .. cursor];
            sig_info.*.signer = signer.ptr;
            sig_info.*.signer_len = signer.len;

            sig_info.*.algo = @tagName(pkey_algo);
            sig_info.*.hash_algo = @tagName(pkey_hash_algo);
        },
    }

    sig_info.*.id_type = @tagName(id_type);
    return true;
}

/// The C code has a separate free function. We should provide one too.
pub fn kmod_module_signature_info_free(sig_info: [*c]c.kmod_signature_info) callconv(.c) void {
    if (sig_info.*.free) |f| f(sig_info);
}
