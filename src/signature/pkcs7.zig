// file: pkcs7/parser.zig
pub const SignerInfos = std.array_list.Managed(SignerInfo);

pub const Pkcs7Error = error{
    Malformed,
    WrongContentType,
    UnsupportedVersion,
    NoSignerInfo,
} || asn1.Asn1Error;

// A simple struct to hold OID data.
pub const OidInfo = struct {
    name: [*:0]const u8,
    // You can add more info here, like key_type, etc.
};

// This creates a compile-time map for efficient OID lookups.
pub const oid_map = std.StaticStringMap(OidInfo).initComptime(&.{
    // --- Hash Algorithm OIDs ---
    .{ "\x2a\x86\x48\x86\xf7\x0d\x02\x05", OidInfo{ .name = "md5" } }, // 1.2.840.113549.2.5
    .{ "\x2b\x0e\x03\x02\x1a", OidInfo{ .name = "sha1" } }, // 1.3.14.3.2.26
    .{ "\x60\x86\x48\x01\x65\x03\x04\x02\x04", OidInfo{ .name = "sha224" } }, // 2.16.840.1.101.3.4.2.4
    .{ "\x60\x86\x48\x01\x65\x03\x04\x02\x01", OidInfo{ .name = "sha256" } }, // 2.16.840.1.101.3.4.2.1
    .{ "\x60\x86\x48\x01\x65\x03\x04\x02\x02", OidInfo{ .name = "sha384" } }, // 2.16.840.1.101.3.4.2.2
    .{ "\x60\x86\x48\x01\x65\x03\x04\x02\x03", OidInfo{ .name = "sha512" } }, // 2.16.840.1.101.3.4.2.3
    .{ "\x2a\x81\x1c\xe5\x52\x01\x04\x01", OidInfo{ .name = "sm3" } }, // 1.2.156.10197.1.401

    // nature Algorithm OIDs (contain key type) ---
    .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", OidInfo{ .name = "RSA" } }, // rsaEncryption
    .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", OidInfo{ .name = "RSA" } }, // sha256WithRSAEncryption
    .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", OidInfo{ .name = "RSA" } }, // sha512WithRSAEncryption
    .{ "\x2a\x86\x48\xce\x38\x04\x01", OidInfo{ .name = "DSA" } }, // dsa
    .{ "\x2a\x86\x48\xce\x3d\x02\x01", OidInfo{ .name = "ECDSA" } }, // ecPublicKey
    .{ "\x2a\x86\x48\xce\x3d\x04\x03\x04", OidInfo{ .name = "ECDSA" } }, // ecdsa-with-SHA512
});

const OID_COMMON_NAME: []const u8 = &.{ 0x55, 0x04, 0x03 }; // 2.5.4.3

// OID for SignedData: 1.2.840.113549.1.7.2
const OID_SIGNED_DATA: []const u8 = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02 };

// Represents AlgorithmIdentifier ::= SEQUENCE { ... }
pub const AlgorithmIdentifier = struct {
    // The raw OID bytes
    oid: []const u8,
    // The raw, optional parameters bytes
    parameters: ?[]const u8,

    pub fn parse(reader: *Asn1Reader) !AlgorithmIdentifier {
        var seq = try reader.enter(.sequence);
        const oid = try seq.readOid();
        const params = if (seq.eof()) null else seq.bytes;
        return .{ .oid = oid, .parameters = params };
    }

    pub fn lookup(self: AlgorithmIdentifier) OidInfo {
        return oid_map.get(self.oid).?;
    }
};

pub const IssuerAndSerialNumber = struct {
    issuer_common_name: ?[]const u8,
    serial_number: []const u8,

    pub fn parse(reader: *Asn1Reader) !IssuerAndSerialNumber {
        var ias_reader = try reader.enter(.sequence);

        // issuer: Name ::= SEQUENCE OF RelativeDistinguishedName
        var name_reader = try ias_reader.enter(.sequence);
        var common_name: ?[]const u8 = null;

        while (!name_reader.eof()) { // Loop over RDNs
            // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
            var rdn_set_reader = try name_reader.enter(.set);
            while (!rdn_set_reader.eof()) { // Loop over attributes in the RDN
                // AttributeTypeAndValue ::= SEQUENCE { type, value }
                var atv_reader = try rdn_set_reader.enter(.sequence);
                const oid = try atv_reader.readOid();

                // The value is ANY, so we read its identifier and then the bytes
                _ = try atv_reader.readIdentifier();
                const value_len = try atv_reader.readLength();
                const value_bytes = try atv_reader.readSlice(value_len);

                if (std.mem.eql(u8, oid, OID_COMMON_NAME)) {
                    common_name = value_bytes;
                }
            }
        }

        const serial = try ias_reader.readInteger();
        if (!ias_reader.eof()) return Pkcs7Error.Malformed;

        return .{
            .issuer_common_name = common_name,
            .serial_number = serial,
        };
    }
};

// Represents SignerIdentifier ::= CHOICE { issuerAndSerialNumber, subjectKeyIdentifier }
pub const SignerIdentifier = struct {
    issuer_and_serial_number: IssuerAndSerialNumber,
};

// Represents SignerInfo ::= SEQUENCE { ... }
// This is the primary structure we want to extract.
pub const SignerInfo = struct {
    version: u8,
    sid: SignerIdentifier,
    digest_algorithm: AlgorithmIdentifier,
    // For simplicity, we are not parsing signed_attrs here, but in a real
    // scenario, you'd parse them to find the messageDigest attribute.
    signed_attrs: ?[]const u8,
    signature_algorithm: AlgorithmIdentifier,
    signature: []const u8,
    unsigned_attrs: ?[]const u8 = null,

    pub fn printDebug(self: SignerInfo) void {
        print("--- SignerInfo ---\n", .{});
        print("  Version: {d}\n", .{self.version});
        print("  SignerID (Issuer): {s}\n", .{self.sid.issuer_and_serial_number.issuer_common_name.?});
        //print("  SignerID (Serial): {f}\n", .{std.fmt.bytesToHex(self.sid.issuer_and_serial_number.serial_number, .lower)});
        print("  Digest Algorithm: {s}\n", .{self.digest_algorithm.lookup().name});
        print("  Signature Algorithm: {s}\n", .{self.signature_algorithm.lookup().name});
        //print("  Signature: {f}\n", .{std.fmt.bytesToHex(self.signature[0..self.signature.len], .lower)});
    }

    pub fn parse(reader: *Asn1Reader) Pkcs7Error!SignerInfo {
        var si_reader = try reader.enter(.sequence);

        const version_bytes = try si_reader.readInteger();
        if (version_bytes.len != 1 or (version_bytes[0] != 1 and version_bytes[0] != 3)) {
            return Pkcs7Error.UnsupportedVersion;
        }
        const version = version_bytes[0];

        // SignerIdentifier is a SEQUENCE
        const ias = try IssuerAndSerialNumber.parse(&si_reader);

        const digest_algo = try AlgorithmIdentifier.parse(&si_reader);

        // Check for optional SignedAttributes [0] IMPLICIT
        var signed_attrs: ?[]const u8 = null;

        {
            // Peek at the next tag without consuming it.
            const next_ident = try si_reader.peekIdentifier();

            if (next_ident.class == .context_specific and next_ident.tag == 0) {
                // The optional field is present. Now we can safely consume it.
                _ = try si_reader.readIdentifier(); // Consume the identifier we just peeked
                const len = try si_reader.readLength();
                signed_attrs = try si_reader.readSlice(len);
            }
        }
        // If the tag wasn't present, the reader's cursor has not moved,
        // and we simply proceed. `signed_attrs` remains null.

        const sig_algo = try AlgorithmIdentifier.parse(&si_reader);

        // Signature ::= OCTET STRING
        const sig_ident = try si_reader.readIdentifier();
        if (sig_ident.tag != @intFromEnum(asn1.Tag.octet_string)) return Pkcs7Error.Malformed;
        const sig_len = try si_reader.readLength();
        const signature = try si_reader.readSlice(sig_len);

        // Check for optional UnsignedAttributes [1] IMPLICIT
        var unsigned_attrs: ?[]const u8 = null;
        if (!si_reader.eof()) {
            // If there's still data, check if it's the optional unsignedAttributes field.
            const next_ident = try si_reader.peekIdentifier();
            if (next_ident.class == .context_specific and next_ident.tag == 1) {
                // It is! Consume it.
                _ = try si_reader.readIdentifier();
                const len = try si_reader.readLength();
                unsigned_attrs = try si_reader.readSlice(len);
            }
        }

        // After parsing all known optional and required fields, the sequence
        // MUST be empty. If it's not, the signature is malformed.
        if (!si_reader.eof()) {
            return Pkcs7Error.Malformed;
        }

        return SignerInfo{
            .version = version,
            .sid = .{ .issuer_and_serial_number = ias },
            .digest_algorithm = digest_algo,
            .signed_attrs = signed_attrs,
            .signature_algorithm = sig_algo,
            .signature = signature,
            .unsigned_attrs = unsigned_attrs, // Populate the new field
        };
    }
};

/// Parses a raw PKCS#7 binary blob (DER format) and extracts all
/// SignerInfo structures contained within.
/// The returned ArrayList and its contents are owned by the caller and must be freed.
pub fn getSignerInfos(alloc: Allocator, pkcs7_data: []const u8) !SignerInfos {
    var reader = Asn1Reader.init(pkcs7_data);

    // 1. Top Level: ContentInfo ::= SEQUENCE
    var content_info_reader = try reader.enter(.sequence);

    // 2. contentType: must be 'signedData'
    const content_type_oid = try content_info_reader.readOid();
    if (!std.mem.eql(u8, content_type_oid, OID_SIGNED_DATA)) {
        return Pkcs7Error.WrongContentType;
    }

    // 3. content: [0] EXPLICIT SignedData
    const content_ident = try content_info_reader.readIdentifier();
    if (content_ident.class != .context_specific or content_ident.tag != 0) {
        return Pkcs7Error.Malformed;
    }
    const content_len = try content_info_reader.readLength();
    var signed_data_outer_reader = Asn1Reader.init(try content_info_reader.readSlice(content_len));

    // 4. SignedData ::= SEQUENCE
    var sd_reader = try signed_data_outer_reader.enter(.sequence);

    // 5. Walk the SignedData structure until we get to SignerInfos
    // We parse lazily, skipping fields we don't need for this specific goal.
    _ = try sd_reader.readInteger(); // version
    _ = try sd_reader.enter(.set); // digestAlgorithms
    _ = try sd_reader.enter(.sequence); // encapContentInfo

    // certificates [0] IMPLICIT SET (optional)
    var next_ident = try sd_reader.readIdentifier();
    if (next_ident.class == .context_specific and next_ident.tag == 0) {
        const len = try sd_reader.readLength();
        _ = try sd_reader.readSlice(len); // Skip certificates
        next_ident = try sd_reader.readIdentifier();
    }

    // crls [1] IMPLICIT SET (optional)
    if (next_ident.class == .context_specific and next_ident.tag == 1) {
        const len = try sd_reader.readLength();
        _ = try sd_reader.readSlice(len); // Skip crls
        next_ident = try sd_reader.readIdentifier();
    }

    // 6. Finally, parse the SignerInfos SET
    if (next_ident.tag != @intFromEnum(asn1.Tag.set)) return Pkcs7Error.Malformed;
    const si_set_len = try sd_reader.readLength();
    var si_set_reader = Asn1Reader.init(try sd_reader.readSlice(si_set_len));

    var signer_infos = std.array_list.Managed(SignerInfo).init(alloc);
    errdefer signer_infos.deinit();

    if (si_set_reader.eof()) return Pkcs7Error.NoSignerInfo;

    while (!si_set_reader.eof()) {
        const info = try SignerInfo.parse(&si_set_reader);
        try signer_infos.append(info);
    }

    return signer_infos;
}

const std = @import("std");
const asn1 = @import("asn1.zig");
const testing = std.testing;
const print = std.debug.print;
const module_parser = @import("module_parser.zig");

const Allocator = std.mem.Allocator;
const Asn1Reader = asn1.Asn1Reader;
