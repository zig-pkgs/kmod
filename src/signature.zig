/// This is to remove dependency on openssl, currently untested
const std = @import("std");
const c = @import("c");
const x509 = std.crypto.Certificate; // Using the provided file
const der = x509.der;

const SIG_MAGIC = "~Module signature appended~\n";

// Module signature information block.
const ModuleSignature = extern struct {
    algo: u8 = 0, // Public-key crypto algorithm [enum pkey_algo] */
    hash: u8 = 0, // Digest algorithm [enum pkey_hash_algo] */
    id_type: u8 = 0, // Key identifier type [enum pkey_id_type] */
    signer_len: u8 = 0, // Length of signer's name */
    key_id_len: u8 = 0, // Length of key identifier */
    __pad: [3]u8 = [1]u8{0} ** 3,
    sig_len: u32 = 0, // Length of signature data (big endian) */

    fn getSigLen(self: ModuleSignature) u32 {
        return std.mem.readInt(u32, std.mem.asBytes(&self.sig_len), .big);
    }
};

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

/// Holds allocated data for a PKCS#7 signature so it can be freed later.
const Pkcs7PrivateData = struct {
    allocator: std.mem.Allocator,
    signer: [:0]const u8,
    key_id: [:0]const u8,
    hash_algo_str: [:0]const u8,

    fn free(data: *Pkcs7PrivateData) void {
        data.allocator.free(data.signer);
        data.allocator.free(data.key_id);
        data.allocator.free(data.hash_algo_str);
        data.allocator.destroy(data);
    }
};

// This is the C-callable free function.
fn pkcs7_free_c(s: ?*anyopaque) callconv(.C) void {
    const sig_info: [*c]c.kmod_signature_info = @ptrCast(@alignCast(s));
    if (sig_info.*.private) |ptr| {
        const private_data: *Pkcs7PrivateData = @ptrCast(@alignCast(ptr));
        private_data.free();
        sig_info.*.private = null;
    }
}

/// Parses the PKCS#7 blob and fills the signature info struct.
/// Returns false on any parsing error.
fn fill_pkcs7(
    allocator: std.mem.Allocator,
    sig_blob: []const u8,
    sig_info: [*c]c.kmod_signature_info,
) !bool {
    // Helper function to get the contents of a DER element from the main blob.
    const contents = struct {
        fn get(elem: der.Element, blob: []const u8) []const u8 {
            return blob[elem.slice.start..elem.slice.end];
        }
    }.get;

    // We'll manually track our position in the sig_blob.
    var cursor: u32 = 0;

    // 1. Top-level SEQUENCE
    const root = try der.Element.parse(sig_blob, cursor);
    if (root.identifier.tag != .sequence) return false;

    // Descend into the root sequence
    cursor = root.slice.start;

    // 2. OID for "signedData"
    const oid_elem = try der.Element.parse(sig_blob, cursor);
    if (oid_elem.identifier.tag != .object_identifier) return false;
    cursor = oid_elem.slice.end;

    // 3. [0] EXPLICIT wrapper for SignedData
    const explicit_elem = try der.Element.parse(sig_blob, cursor);
    if (explicit_elem.identifier.class != .context_specific or @intFromEnum(explicit_elem.identifier.tag) != 0) return false;

    // Descend into the explicit wrapper's contents
    cursor = explicit_elem.slice.start;

    // 4. SignedData SEQUENCE
    const signed_data = try der.Element.parse(sig_blob, cursor);
    if (signed_data.identifier.tag != .sequence) return false;

    // Descend into the SignedData sequence
    cursor = signed_data.slice.start;

    // 5. Navigate SignedData fields to find SignerInfos
    var signer_infos_elem: ?der.Element = null;
    while (cursor < signed_data.slice.end) {
        const elem = try der.Element.parse(sig_blob, cursor);
        cursor = elem.slice.end; // Advance to the next sibling element

        // SignerInfos is a SET OF (tag 17)
        if (elem.identifier.tag == .sequence_of) {
            signer_infos_elem = elem;
            break;
        }
    }
    if (signer_infos_elem == null) return false;

    // Descend into the SignerInfos SET
    cursor = signer_infos_elem.?.slice.start;

    // 6. Get the first SignerInfo SEQUENCE from the SET
    const signer_info_seq = try der.Element.parse(sig_blob, cursor);
    if (signer_info_seq.identifier.tag != .sequence) return false;

    // Descend into the SignerInfo sequence
    cursor = signer_info_seq.slice.start;

    // 7. Parse the fields of SignerInfo
    const version_elem = try der.Element.parse(sig_blob, cursor);
    cursor = version_elem.slice.end;
    const issuer_and_serial = try der.Element.parse(sig_blob, cursor);
    cursor = issuer_and_serial.slice.end;
    const digest_algo = try der.Element.parse(sig_blob, cursor);
    cursor = digest_algo.slice.end;

    // Skip optional authenticatedAttributes [0]
    var next_elem = try der.Element.parse(sig_blob, cursor);
    if (next_elem.identifier.class == .context_specific) {
        cursor = next_elem.slice.end;
        next_elem = try der.Element.parse(sig_blob, cursor);
    }
    cursor = next_elem.slice.end;

    const enc_digest = try der.Element.parse(sig_blob, cursor);

    // 8. Extract the data we need
    // a. Signature
    sig_info.*.sig = @ptrCast(contents(enc_digest, sig_blob));

    // b. Signer and Key ID from issuerAndSerialNumber
    const pvt = try allocator.create(Pkcs7PrivateData);
    pvt.allocator = allocator;
    var ias_cursor = issuer_and_serial.slice.start;
    const issuer_name_seq = try der.Element.parse(sig_blob, ias_cursor);
    ias_cursor = issuer_name_seq.slice.end;
    const serial_num_elem = try der.Element.parse(sig_blob, ias_cursor);
    pvt.key_id = try allocator.dupeZ(u8, contents(serial_num_elem, sig_blob));

    // Walk the issuer name to find the Common Name
    var issuer_cursor = issuer_name_seq.slice.start;
    var common_name: []const u8 = "unknown";
    while (issuer_cursor < issuer_name_seq.slice.end) {
        const attr_set = try der.Element.parse(sig_blob, issuer_cursor);
        issuer_cursor = attr_set.slice.end;

        const attr_seq = try der.Element.parse(sig_blob, attr_set.slice.start);
        const attr_oid = try der.Element.parse(sig_blob, attr_seq.slice.start);
        const attr_val = try der.Element.parse(sig_blob, attr_oid.slice.end);
        const attr_type = x509.parseAttribute(contents(attr_oid, sig_blob), attr_oid) catch continue;
        if (attr_type == .commonName) {
            common_name = contents(attr_val, sig_blob);
            break;
        }
    }
    pvt.signer = try allocator.dupeZ(u8, common_name);

    // c. Hash Algorithm
    const hash_algo_oid = try der.Element.parse(contents(digest_algo, sig_blob), 0);
    const hash_enum = x509.parseAlgorithm(contents(hash_algo_oid, sig_blob), hash_algo_oid) catch {
        std.log.warn("unrecognized hash OID", .{});
        return false;
    };
    const hash_algo_name = switch (hash_enum) {
        .sha256WithRSAEncryption => "sha256",
        .sha512WithRSAEncryption => "sha512",
        .sha1WithRSAEncryption => "sha1",
        else => "unknown",
    };
    pvt.hash_algo_str = try allocator.dupeZ(u8, hash_algo_name);

    // 9. Set up the private data for freeing memory (your implementation was correct)
    sig_info.*.key_id = @ptrCast(pvt.key_id);
    sig_info.*.signer = @ptrCast(pvt.signer);
    sig_info.*.hash_algo = @ptrCast(pvt.hash_algo_str);
    sig_info.*.private = pvt;
    sig_info.*.free = pkcs7_free_c;

    return true;
}

pub fn kmod_module_signature_info(
    file: [*c]const c.kmod_file,
    sig_info: [*c]c.kmod_signature_info,
) callconv(.C) bool {
    const size: usize = @intCast(c.kmod_file_get_size(file));
    const content_ptr: [*]u8 = @ptrCast(@alignCast(c.kmod_file_get_contents(file)));
    const contents = content_ptr[0..size];

    // 1. Check for and strip the magic string
    if (!std.mem.endsWith(u8, contents, SIG_MAGIC)) {
        return false; // C returns bool (0 for false)
    }
    const without_magic = contents[0 .. contents.len - SIG_MAGIC.len];

    // 2. Check for and read the `module_signature` struct
    if (without_magic.len < @sizeOf(ModuleSignature)) {
        return false;
    }
    const modsig_offset = without_magic.len - @sizeOf(ModuleSignature);
    var modsig: ModuleSignature = undefined;
    @memcpy(std.mem.asBytes(&modsig), without_magic[modsig_offset .. modsig_offset + @sizeOf(ModuleSignature)]);

    // 3. Sanity checks from the C code
    const id_type = std.meta.intToEnum(PkeyIdType, modsig.id_type) catch return false;
    const pkey_algo = std.meta.intToEnum(PkeyAlgo, modsig.algo) catch return false;
    const pkey_hash_algo: PkeyHashAlgo = std.meta.intToEnum(PkeyHashAlgo, modsig.hash) catch return false;

    const sig_len = modsig.getSigLen();
    const data_payload_len = @as(u64, sig_len) + modsig.signer_len + modsig.key_id_len;
    //const module_data_and_sig_ptr = without_magic.ptr;
    const sig_trailer_len = @sizeOf(ModuleSignature);

    if (sig_len == 0 or (without_magic.len - sig_trailer_len) < data_payload_len) {
        return false;
    }

    // 4. Fill the sig_info struct based on id_type
    const sig_data_end = modsig_offset;
    var ret: bool = true;
    _ = &ret;

    switch (id_type) {
        .@"PKCS#7" => {
            //const sig_blob = without_magic[sig_data_end - sig_len .. sig_data_end];
            // Use C allocator so the C side can handle freeing if needed, though our
            // `free` function makes this self-contained.
            //ret = fill_pkcs7(std.heap.c_allocator, sig_blob, sig_info) catch return false;
            // Algo is determined by the signature itself, but we can set the outer one.
            sig_info.*.algo = @tagName(pkey_algo);

            const unknown_stub = "unknown";
            sig_info.*.signer = unknown_stub;
            sig_info.*.signer_len = unknown_stub.len;
            sig_info.*.key_id = unknown_stub;
            sig_info.*.key_id_len = unknown_stub.len;
            sig_info.*.sig = unknown_stub;
            sig_info.*.sig_len = unknown_stub.len;
            sig_info.*.hash_algo = @tagName(pkey_hash_algo);
        },
        .PGP, .X509 => {
            // This is the `fill_default` case
            var cursor = sig_data_end;
            sig_info.*.sig = @ptrCast(without_magic[cursor - sig_len .. cursor]);
            cursor -= sig_len;
            sig_info.*.key_id = @ptrCast(without_magic[cursor - modsig.key_id_len .. cursor]);
            cursor -= modsig.key_id_len;
            sig_info.*.signer = @ptrCast(without_magic[cursor - modsig.signer_len .. cursor]);

            sig_info.*.algo = @tagName(pkey_algo);
            sig_info.*.hash_algo = @tagName(pkey_hash_algo);
        },
    }

    sig_info.*.id_type = @tagName(id_type);
    return ret;
}

/// The C code has a separate free function. We should provide one too.
pub fn kmod_module_signature_info_free(sig_info: [*c]c.kmod_signature_info) callconv(.C) void {
    if (sig_info.*.free) |f| f(sig_info);
}
