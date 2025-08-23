// file: pkcs7/asn1.zig
const std = @import("std");

pub const Asn1Error = error{
    UnexpectedEof,
    InvalidTag,
    InvalidLength,
    ConstraintViolation,
};

pub const Class = enum(u2) {
    universal = 0,
    application = 1,
    context_specific = 2,
    private = 3,
};
pub const PnC = enum(u1) {
    primitive = 0,
    constructed = 1,
};
pub const Tag = enum(u5) {
    end_of_content = 0,
    boolean = 1,
    integer = 2,
    bit_string = 3,
    octet_string = 4,
    null = 5,
    object_identifier = 6,
    sequence = 16,
    set = 17,
    printable_string = 19,
    t61_string = 20,
    ia5_string = 22,
    utc_time = 23,
    generalized_time = 24,
    // We only need a subset for PKCS7
};

pub const Asn1Identifier = struct {
    class: Class,
    pnc: PnC,
    tag: u8,
};

pub const Asn1Reader = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) Asn1Reader {
        return .{ .bytes = bytes };
    }

    pub fn eof(self: Asn1Reader) bool {
        return self.bytes.len == 0;
    }

    fn readByte(self: *Asn1Reader) !u8 {
        if (self.bytes.len < 1) return Asn1Error.UnexpectedEof;
        const byte = self.bytes[0];
        self.bytes = self.bytes[1..];
        return byte;
    }

    pub fn readIdentifier(self: *Asn1Reader) !Asn1Identifier {
        const ident_byte = try self.readByte();
        // We don't support multi-byte tags for simplicity here.
        if ((ident_byte & 0x1F) == 0x1F) return Asn1Error.InvalidTag;

        return .{
            .class = @enumFromInt((ident_byte >> 6) & 0b11),
            .pnc = @enumFromInt((ident_byte >> 5) & 0b1),
            .tag = ident_byte & 0b11111,
        };
    }

    /// Peeks at the next identifier without advancing the reader's cursor.
    pub fn peekIdentifier(self: Asn1Reader) !Asn1Identifier {
        var temp_reader = self; // Create a copy of the reader
        return try temp_reader.readIdentifier(); // Operate on the copy
    }

    pub fn readLength(self: *Asn1Reader) !usize {
        const len_byte = try self.readByte();
        if ((len_byte & 0x80) == 0) {
            // Short form
            return len_byte;
        }

        // Long form
        const num_octets = len_byte & 0x7F;
        if (num_octets == 0) return Asn1Error.InvalidLength; // Indefinite length not supported
        if (num_octets > @sizeOf(usize)) return Asn1Error.InvalidLength; // Length too large for arch
        if (self.bytes.len < num_octets) return Asn1Error.UnexpectedEof;

        var len: usize = 0;
        for (self.bytes[0..num_octets]) |byte| {
            len = (len << 8) | byte;
        }

        self.bytes = self.bytes[num_octets..];
        return len;
    }

    pub fn readSlice(self: *Asn1Reader, len: usize) ![]const u8 {
        if (self.bytes.len < len) return Asn1Error.UnexpectedEof;
        const slice = self.bytes[0..len];
        self.bytes = self.bytes[len..];
        return slice;
    }

    pub fn enter(self: *Asn1Reader, expected_tag: Tag) !Asn1Reader {
        const ident = try self.readIdentifier();
        if (ident.class != .universal or ident.tag != @intFromEnum(expected_tag)) {
            return Asn1Error.InvalidTag;
        }

        const len = try self.readLength();
        const inner_bytes = try self.readSlice(len);
        return .init(inner_bytes);
    }

    pub fn readInteger(self: *Asn1Reader) ![]const u8 {
        const ident = try self.readIdentifier();
        if (ident.tag != @intFromEnum(Tag.integer)) return Asn1Error.InvalidTag;
        const len = try self.readLength();
        return self.readSlice(len);
    }

    pub fn readOid(self: *Asn1Reader) ![]const u8 {
        const ident = try self.readIdentifier();
        if (ident.tag != @intFromEnum(Tag.object_identifier)) return Asn1Error.InvalidTag;
        const len = try self.readLength();
        return self.readSlice(len);
    }
};
