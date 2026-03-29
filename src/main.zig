const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;

/// HPKE operation mode per RFC 9180 Section 5.1.
pub const Mode = enum(u8) { base = 0, psk = 1, auth = 2, auth_psk = 3 };

/// Key Encapsulation Mechanism identifier.
pub const KemId = enum(u16) {
    p256_sha256 = 0x0010,
    p384_sha384 = 0x0011,
    x25519_sha256 = 0x0020,
    ml_kem_512 = 0x0040,
    ml_kem_768 = 0x0041,
    ml_kem_1024 = 0x0042,
    mlkem768_p256 = 0x0050,
    mlkem1024_p384 = 0x0051,
    mlkem768_x25519 = 0x647a,

    pub fn kemFlavor(self: KemId) enum { dhkem, pqkem } {
        return switch (self) {
            .p256_sha256, .p384_sha384, .x25519_sha256 => .dhkem,
            else => .pqkem,
        };
    }

    /// Returns the KDF naturally paired with this DHKEM, or null for PQ KEMs.
    pub fn kdf(self: KemId) ?KdfId {
        return switch (self) {
            .x25519_sha256, .p256_sha256 => .hkdf_sha256,
            .p384_sha384 => .hkdf_sha384,
            else => null,
        };
    }

    pub fn nSecret(self: KemId) u16 {
        return switch (self) {
            .p384_sha384 => 48,
            else => 32,
        };
    }

    fn NistCurve(comptime self: KemId) type {
        return switch (self) {
            .p256_sha256 => crypto.ecc.P256,
            .p384_sha384 => crypto.ecc.P384,
            else => @compileError("not a NIST curve KEM"),
        };
    }

    fn PqKem(comptime self: KemId) type {
        return switch (self) {
            .ml_kem_512 => crypto.kem.ml_kem.MLKem512,
            .ml_kem_768 => crypto.kem.ml_kem.MLKem768,
            .ml_kem_1024 => crypto.kem.ml_kem.MLKem1024,
            .mlkem768_x25519 => crypto.kem.hybrid.MlKem768X25519,
            .mlkem768_p256 => crypto.kem.hybrid.MlKem768P256,
            .mlkem1024_p384 => crypto.kem.hybrid.MlKem1024P384,
            else => @compileError("not a PQ KEM"),
        };
    }

    fn kemNsk(comptime self: KemId) usize {
        return switch (self) {
            .ml_kem_512, .ml_kem_768, .ml_kem_1024 => 64,
            .mlkem768_p256, .mlkem1024_p384, .mlkem768_x25519 => 32,
            else => @compileError("not a PQ KEM"),
        };
    }

    fn makeKemSuiteId(self: KemId) [5]u8 {
        var id: [5]u8 = undefined;
        @memcpy(id[0..3], "KEM");
        mem.writeInt(u16, id[3..5], @intFromEnum(self), .big);
        return id;
    }
};

/// Key Derivation Function identifier.
pub const KdfId = enum(u16) {
    hkdf_sha256 = 0x0001,
    hkdf_sha384 = 0x0002,
    hkdf_sha512 = 0x0003,
    shake128 = 0x0010,
    shake256 = 0x0011,
    turboshake128 = 0x0012,
    turboshake256 = 0x0013,

    pub fn kdfFlavor(self: KdfId) enum { two_stage, one_stage } {
        return switch (self) {
            .hkdf_sha256, .hkdf_sha384, .hkdf_sha512 => .two_stage,
            else => .one_stage,
        };
    }

    pub fn hashLength(self: KdfId) u16 {
        return switch (self) {
            .hkdf_sha256 => 32,
            .hkdf_sha384 => 48,
            .hkdf_sha512 => 64,
            .shake128, .turboshake128 => 32,
            .shake256, .turboshake256 => 64,
        };
    }

    fn Hmac(comptime self: KdfId) type {
        return switch (self) {
            .hkdf_sha256 => crypto.auth.hmac.sha2.HmacSha256,
            .hkdf_sha384 => crypto.auth.hmac.sha2.HmacSha384,
            .hkdf_sha512 => crypto.auth.hmac.sha2.HmacSha512,
            else => @compileError("not a two-stage KDF"),
        };
    }

    fn Xof(comptime self: KdfId) type {
        return switch (self) {
            .shake128 => crypto.hash.sha3.Shake128,
            .shake256 => crypto.hash.sha3.Shake256,
            .turboshake128 => crypto.hash.sha3.TurboShake128(null),
            .turboshake256 => crypto.hash.sha3.TurboShake256(null),
            else => @compileError("not a one-stage KDF"),
        };
    }
};

/// Authenticated Encryption with Associated Data identifier.
pub const AeadId = enum(u16) {
    aes128_gcm = 1,
    aes256_gcm = 2,
    chacha20_poly1305 = 3,
    export_only = 0xFFFF,

    fn Primitive(comptime self: AeadId) type {
        return switch (self) {
            .aes128_gcm => crypto.aead.aes_gcm.Aes128Gcm,
            .aes256_gcm => crypto.aead.aes_gcm.Aes256Gcm,
            .chacha20_poly1305 => crypto.aead.chacha_poly.ChaCha20Poly1305,
            .export_only => @compileError("export_only has no AEAD primitive"),
        };
    }
};

/// Identifies a complete HPKE cipher suite (KEM + KDF + AEAD combination).
pub const CipherSuiteId = enum(u16) {
    x25519_hkdf_sha256_aes128_gcm = 0x0001,
    x25519_hkdf_sha256_aes256_gcm = 0x0002,
    x25519_hkdf_sha256_chacha20_poly1305 = 0x0003,
    x25519_hkdf_sha384_aes256_gcm = 0x0012,
    x25519_hkdf_sha512_aes256_gcm = 0x0022,
    x25519_hkdf_sha256_export_only = 0x00FF,
    p256_hkdf_sha256_aes128_gcm = 0x0101,
    p256_hkdf_sha256_aes256_gcm = 0x0102,
    p256_hkdf_sha256_chacha20_poly1305 = 0x0103,
    p384_hkdf_sha384_aes256_gcm = 0x0202,
    p384_hkdf_sha384_chacha20_poly1305 = 0x0203,
    ml_kem_512_hkdf_sha256_aes128_gcm = 0x0401,
    ml_kem_768_hkdf_sha256_aes128_gcm = 0x0411,
    ml_kem_1024_hkdf_sha384_aes256_gcm = 0x0422,
    mlkem768_p256_hkdf_sha256_aes128_gcm = 0x0501,
    mlkem1024_p384_hkdf_sha384_aes256_gcm = 0x0512,
    mlkem768_x25519_hkdf_sha256_chacha20_poly1305 = 0x6403,
    p256_shake128_aes128_gcm = 0x1001,
    p384_shake256_aes256_gcm = 0x1102,
    x25519_turboshake128_chacha20_poly1305 = 0x1203,
    mlkem768_p256_shake128_aes256_gcm = 0x1502,
    mlkem768_x25519_shake256_chacha20_poly1305 = 0x1163,
    ml_kem_1024_turboshake256_aes128_gcm = 0x1341,

    const Components = struct { kem: KemId, kdf: KdfId, aead: AeadId };

    const suite_map: std.enums.EnumArray(CipherSuiteId, Components) = .init(.{
        .x25519_hkdf_sha256_aes128_gcm = .{ .kem = .x25519_sha256, .kdf = .hkdf_sha256, .aead = .aes128_gcm },
        .x25519_hkdf_sha256_aes256_gcm = .{ .kem = .x25519_sha256, .kdf = .hkdf_sha256, .aead = .aes256_gcm },
        .x25519_hkdf_sha256_chacha20_poly1305 = .{ .kem = .x25519_sha256, .kdf = .hkdf_sha256, .aead = .chacha20_poly1305 },
        .x25519_hkdf_sha384_aes256_gcm = .{ .kem = .x25519_sha256, .kdf = .hkdf_sha384, .aead = .aes256_gcm },
        .x25519_hkdf_sha512_aes256_gcm = .{ .kem = .x25519_sha256, .kdf = .hkdf_sha512, .aead = .aes256_gcm },
        .x25519_hkdf_sha256_export_only = .{ .kem = .x25519_sha256, .kdf = .hkdf_sha256, .aead = .export_only },
        .p256_hkdf_sha256_aes128_gcm = .{ .kem = .p256_sha256, .kdf = .hkdf_sha256, .aead = .aes128_gcm },
        .p256_hkdf_sha256_aes256_gcm = .{ .kem = .p256_sha256, .kdf = .hkdf_sha256, .aead = .aes256_gcm },
        .p256_hkdf_sha256_chacha20_poly1305 = .{ .kem = .p256_sha256, .kdf = .hkdf_sha256, .aead = .chacha20_poly1305 },
        .p384_hkdf_sha384_aes256_gcm = .{ .kem = .p384_sha384, .kdf = .hkdf_sha384, .aead = .aes256_gcm },
        .p384_hkdf_sha384_chacha20_poly1305 = .{ .kem = .p384_sha384, .kdf = .hkdf_sha384, .aead = .chacha20_poly1305 },
        .ml_kem_512_hkdf_sha256_aes128_gcm = .{ .kem = .ml_kem_512, .kdf = .hkdf_sha256, .aead = .aes128_gcm },
        .ml_kem_768_hkdf_sha256_aes128_gcm = .{ .kem = .ml_kem_768, .kdf = .hkdf_sha256, .aead = .aes128_gcm },
        .ml_kem_1024_hkdf_sha384_aes256_gcm = .{ .kem = .ml_kem_1024, .kdf = .hkdf_sha384, .aead = .aes256_gcm },
        .mlkem768_p256_hkdf_sha256_aes128_gcm = .{ .kem = .mlkem768_p256, .kdf = .hkdf_sha256, .aead = .aes128_gcm },
        .mlkem1024_p384_hkdf_sha384_aes256_gcm = .{ .kem = .mlkem1024_p384, .kdf = .hkdf_sha384, .aead = .aes256_gcm },
        .mlkem768_x25519_hkdf_sha256_chacha20_poly1305 = .{ .kem = .mlkem768_x25519, .kdf = .hkdf_sha256, .aead = .chacha20_poly1305 },
        .p256_shake128_aes128_gcm = .{ .kem = .p256_sha256, .kdf = .shake128, .aead = .aes128_gcm },
        .p384_shake256_aes256_gcm = .{ .kem = .p384_sha384, .kdf = .shake256, .aead = .aes256_gcm },
        .x25519_turboshake128_chacha20_poly1305 = .{ .kem = .x25519_sha256, .kdf = .turboshake128, .aead = .chacha20_poly1305 },
        .mlkem768_p256_shake128_aes256_gcm = .{ .kem = .mlkem768_p256, .kdf = .shake128, .aead = .aes256_gcm },
        .mlkem768_x25519_shake256_chacha20_poly1305 = .{ .kem = .mlkem768_x25519, .kdf = .shake256, .aead = .chacha20_poly1305 },
        .ml_kem_1024_turboshake256_aes128_gcm = .{ .kem = .ml_kem_1024, .kdf = .turboshake256, .aead = .aes128_gcm },
    });

    /// Looks up the suite ID for a given KEM/KDF/AEAD triple, or null if unsupported.
    pub fn fromComponents(kem: KemId, kdf: KdfId, aead: AeadId) ?CipherSuiteId {
        inline for (@typeInfo(CipherSuiteId).@"enum".fields) |f| {
            const id: CipherSuiteId = @enumFromInt(f.value);
            const c = comptime suite_map.get(id);
            if (c.kem == kem and c.kdf == kdf and c.aead == aead) return id;
        }
        return null;
    }

    /// Decomposes this suite ID into its KEM, KDF, and AEAD components.
    pub fn getComponents(self: CipherSuiteId) Components {
        return suite_map.get(self);
    }
};

const max_hash_length = 64;
const max_key_length = 32;
const max_nonce_length = 12;
const max_tag_length = 16;
const max_enc_length = 1665;
const max_public_key_length = 1665;
const max_secret_key_length = 64;
const max_shared_length = 96; // 2x for auth mode dual-DH

/// Resolved parameters for a given `CipherSuiteId` -- key lengths, hash sizes, etc.
pub const CipherSuite = struct {
    id: CipherSuiteId,
    kem: KemId,
    kdf: KdfId,
    aead: AeadId,
    public_key_length: u16,
    secret_key_length: u16,
    enc_length: u16,
    hash_length: u16,
    key_length: u16,
    nonce_length: u16,
    tag_length: u16,

    pub fn init(suite_id: CipherSuiteId) CipherSuite {
        const components = suite_id.getComponents();

        const kem_sizes: struct { pk: u16, sk: u16, enc: u16 } = switch (components.kem) {
            .x25519_sha256 => .{ .pk = 32, .sk = 32, .enc = 32 },
            .p256_sha256 => .{ .pk = 65, .sk = 32, .enc = 65 },
            .p384_sha384 => .{ .pk = 97, .sk = 48, .enc = 97 },
            .ml_kem_512 => .{ .pk = 800, .sk = 64, .enc = 768 },
            .ml_kem_768 => .{ .pk = 1184, .sk = 64, .enc = 1088 },
            .ml_kem_1024 => .{ .pk = 1568, .sk = 64, .enc = 1568 },
            .mlkem768_p256 => .{ .pk = 1249, .sk = 32, .enc = 1153 },
            .mlkem1024_p384 => .{ .pk = 1665, .sk = 32, .enc = 1665 },
            .mlkem768_x25519 => .{ .pk = 1216, .sk = 32, .enc = 1120 },
        };

        return .{
            .id = suite_id,
            .kem = components.kem,
            .kdf = components.kdf,
            .aead = components.aead,
            .public_key_length = kem_sizes.pk,
            .secret_key_length = kem_sizes.sk,
            .enc_length = kem_sizes.enc,
            .hash_length = components.kdf.hashLength(),
            .key_length = switch (components.aead) {
                .aes128_gcm => 16,
                .aes256_gcm => 32,
                .chacha20_poly1305 => 32,
                .export_only => 0,
            },
            .nonce_length = switch (components.aead) {
                .aes128_gcm, .aes256_gcm, .chacha20_poly1305 => 12,
                .export_only => 0,
            },
            .tag_length = switch (components.aead) {
                .aes128_gcm, .aes256_gcm, .chacha20_poly1305 => 16,
                .export_only => 0,
            },
        };
    }

    fn makeSuiteId(self: *const CipherSuite) [10]u8 {
        var id: [10]u8 = undefined;
        @memcpy(id[0..4], "HPKE");
        mem.writeInt(u16, id[4..6], @intFromEnum(self.kem), .big);
        mem.writeInt(u16, id[6..8], @intFromEnum(self.kdf), .big);
        mem.writeInt(u16, id[8..10], @intFromEnum(self.aead), .big);
        return id;
    }
};

pub const ExportOnlyError = error{ExportOnlyMode};
pub const MessageLimitError = error{MessageLimitReached};
pub const SealError = ExportOnlyError || MessageLimitError || crypto.errors.EncodingError;
pub const OpenError = ExportOnlyError || MessageLimitError || crypto.errors.EncodingError || crypto.errors.AuthenticationError;

/// Sender encryption context for a single HPKE session.
pub const SenderContext = struct {
    suite: CipherSuite,
    key: [max_key_length]u8,
    base_nonce: [max_nonce_length]u8,
    sequence: u64,
    exporter_secret: [max_hash_length]u8,

    pub fn seal(self: *SenderContext, out: []u8, plaintext: []const u8, aad: []const u8) SealError!void {
        if (self.suite.aead == .export_only) return error.ExportOnlyMode;
        if (out.len != plaintext.len + self.suite.tag_length) return error.InvalidEncoding;
        if (self.sequence == std.math.maxInt(u64)) return error.MessageLimitReached;

        const nonce = computeNonce(self.base_nonce[0..self.suite.nonce_length], self.sequence, self.suite.nonce_length);

        switch (self.suite.aead) {
            inline .aes128_gcm, .aes256_gcm, .chacha20_poly1305 => |aead_tag| {
                const Aead = aead_tag.Primitive();
                var tag_array: [Aead.tag_length]u8 = undefined;
                Aead.encrypt(out[0..plaintext.len], &tag_array, plaintext, aad, nonce, self.key[0..Aead.key_length].*);
                @memcpy(out[plaintext.len..][0..Aead.tag_length], &tag_array);
            },
            .export_only => unreachable,
        }

        self.sequence += 1;
    }

    pub fn exportSecret(self: *const SenderContext, out: []u8, exporter_context: []const u8) void {
        exportSecretImpl(self.suite, &self.exporter_secret, out, exporter_context);
    }
};

/// Recipient decryption context for a single HPKE session.
pub const RecipientContext = struct {
    suite: CipherSuite,
    key: [max_key_length]u8,
    base_nonce: [max_nonce_length]u8,
    sequence: u64,
    exporter_secret: [max_hash_length]u8,

    pub fn open(self: *RecipientContext, out: []u8, ciphertext_with_tag: []const u8, aad: []const u8) OpenError!void {
        if (self.suite.aead == .export_only) return error.ExportOnlyMode;
        if (ciphertext_with_tag.len < self.suite.tag_length) return error.InvalidEncoding;
        if (out.len != ciphertext_with_tag.len - self.suite.tag_length) return error.InvalidEncoding;
        if (self.sequence == std.math.maxInt(u64)) return error.MessageLimitReached;

        const nonce = computeNonce(self.base_nonce[0..self.suite.nonce_length], self.sequence, self.suite.nonce_length);
        const ct_len = ciphertext_with_tag.len - self.suite.tag_length;

        switch (self.suite.aead) {
            inline .aes128_gcm, .aes256_gcm, .chacha20_poly1305 => |aead_tag| {
                const Aead = aead_tag.Primitive();
                try Aead.decrypt(out, ciphertext_with_tag[0..ct_len], ciphertext_with_tag[ct_len..][0..Aead.tag_length].*, aad, nonce, self.key[0..Aead.key_length].*);
            },
            .export_only => unreachable,
        }

        self.sequence += 1;
    }

    pub fn exportSecret(self: *const RecipientContext, out: []u8, exporter_context: []const u8) void {
        exportSecretImpl(self.suite, &self.exporter_secret, out, exporter_context);
    }
};

fn exportSecretImpl(suite: CipherSuite, exporter_secret: *const [max_hash_length]u8, out: []u8, exporter_context: []const u8) void {
    const suite_id = suite.makeSuiteId();
    if (suite.kdf.kdfFlavor() == .one_stage) {
        xofLabeledDerive(suite.kdf, exporter_secret[0..suite.hash_length], "sec", exporter_context, &suite_id, out);
    } else {
        labeledExpand(suite.kdf, exporter_secret[0..suite.hash_length], "sec", exporter_context, &suite_id, out);
    }
}

fn computeNonce(base: []const u8, seq: u64, nn: u16) [max_nonce_length]u8 {
    var nonce: [max_nonce_length]u8 = @splat(0);
    @memcpy(nonce[0..nn], base);

    var seq_bytes: [8]u8 = undefined;
    mem.writeInt(u64, &seq_bytes, seq, .big);

    const offset = if (nn >= 8) nn - 8 else 0;
    const seq_offset = if (nn < 8) 8 - nn else 0;
    const len = @min(nn, 8);

    for (0..len) |i| {
        nonce[offset + i] ^= seq_bytes[seq_offset + i];
    }
    return nonce;
}

pub const SetupError = crypto.errors.IdentityElementError ||
    crypto.errors.EncodingError ||
    crypto.errors.NonCanonicalError ||
    crypto.errors.NotSquareError ||
    crypto.errors.WeakPublicKeyError ||
    crypto.errors.WeakParametersError;

/// Result of a sender setup: the encapsulated key and the encryption context.
pub const SenderResult = struct {
    enc: [max_enc_length]u8,
    enc_length: usize,
    ctx: SenderContext,
};

/// HPKE (Hybrid Public Key Encryption) per RFC 9180 and draft-ietf-hpke-pq-04.
pub const Hpke = struct {
    suite: CipherSuite,

    pub fn init(suite_id: CipherSuiteId) Hpke {
        return .{ .suite = CipherSuite.init(suite_id) };
    }

    pub fn senderSetup(self: *const Hpke, pk_r: []const u8, info: []const u8, io: std.Io) SetupError!SenderResult {
        return self.senderSetupCommon(pk_r, info, .base, "", "", null, io);
    }

    pub fn senderSetupDeterministic(self: *const Hpke, pk_r: []const u8, info: []const u8, sk_e: []const u8) SetupError!SenderResult {
        return self.senderSetupDeterministicCommon(pk_r, info, .base, "", "", sk_e, null);
    }

    pub fn senderSetupDeterministicPSK(self: *const Hpke, pk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, sk_e: []const u8) SetupError!SenderResult {
        return self.senderSetupDeterministicCommon(pk_r, info, .psk, psk, psk_id, sk_e, null);
    }

    pub fn senderSetupDeterministicAuth(self: *const Hpke, pk_r: []const u8, info: []const u8, sk_s: []const u8, sk_e: []const u8) SetupError!SenderResult {
        return self.senderSetupDeterministicCommon(pk_r, info, .auth, "", "", sk_e, sk_s);
    }

    pub fn senderSetupDeterministicAuthPSK(self: *const Hpke, pk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, sk_s: []const u8, sk_e: []const u8) SetupError!SenderResult {
        return self.senderSetupDeterministicCommon(pk_r, info, .auth_psk, psk, psk_id, sk_e, sk_s);
    }

    pub fn recipientSetup(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8) SetupError!RecipientContext {
        return self.recipientSetupCommon(enc, sk_r, info, .base, "", "", null);
    }

    pub fn senderSetupPSK(self: *const Hpke, pk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, io: std.Io) SetupError!SenderResult {
        return self.senderSetupCommon(pk_r, info, .psk, psk, psk_id, null, io);
    }

    pub fn recipientSetupPSK(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8) SetupError!RecipientContext {
        return self.recipientSetupCommon(enc, sk_r, info, .psk, psk, psk_id, null);
    }

    pub fn senderSetupAuth(self: *const Hpke, pk_r: []const u8, info: []const u8, sk_s: []const u8, io: std.Io) SetupError!SenderResult {
        return self.senderSetupCommon(pk_r, info, .auth, "", "", sk_s, io);
    }

    pub fn recipientSetupAuth(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8, pk_s: []const u8) SetupError!RecipientContext {
        return self.recipientSetupCommon(enc, sk_r, info, .auth, "", "", pk_s);
    }

    pub fn senderSetupAuthPSK(self: *const Hpke, pk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, sk_s: []const u8, io: std.Io) SetupError!SenderResult {
        return self.senderSetupCommon(pk_r, info, .auth_psk, psk, psk_id, sk_s, io);
    }

    pub fn recipientSetupAuthPSK(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, pk_s: []const u8) SetupError!RecipientContext {
        return self.recipientSetupCommon(enc, sk_r, info, .auth_psk, psk, psk_id, pk_s);
    }

    const DerivedKeyPair = struct { sk: [max_secret_key_length]u8, pk: [max_public_key_length]u8 };
    const PqEncapResult = struct { shared_secret: [32]u8, enc: [max_enc_length]u8, enc_len: usize };

    pub fn deriveKeyPair(self: *const Hpke, seed: []const u8) DerivedKeyPair {
        const kem_suite_id = self.suite.kem.makeKemSuiteId();

        if (self.suite.kem.kemFlavor() == .pqkem) {
            return pqDeriveKeyPair(self.suite.kem, seed, &kem_suite_id);
        }

        var sk: [max_secret_key_length]u8 = @splat(0);
        var pk: [max_public_key_length]u8 = @splat(0);

        const kem_kdf = self.suite.kem.kdf().?;
        const n_secret = self.suite.kem.nSecret();
        var prk: [max_hash_length]u8 = undefined;
        labeledExtract(kem_kdf, "", "dkp_prk", seed, &kem_suite_id, prk[0..n_secret]);

        switch (self.suite.kem) {
            .x25519_sha256 => {
                labeledExpand(kem_kdf, prk[0..n_secret], "sk", "", &kem_suite_id, sk[0..32]);
                const pk_32 = crypto.dh.X25519.recoverPublicKey(sk[0..32].*) catch unreachable;
                @memcpy(pk[0..32], &pk_32);
            },
            inline .p256_sha256, .p384_sha384 => |tag| {
                const Curve = tag.NistCurve();
                const n = comptime tag.nSecret();
                var counter: u8 = 0;
                while (true) : (counter += 1) {
                    if (counter > 255) unreachable;
                    labeledExpand(kem_kdf, prk[0..n_secret], "candidate", &[_]u8{counter}, &kem_suite_id, sk[0..n]);
                    sk[0] &= 0xFF;
                    const sk_int = mem.readInt(std.meta.Int(.unsigned, n * 8), sk[0..n], .big);
                    if (sk_int == 0 or sk_int >= Curve.scalar.field_order) continue;
                    break;
                }
                const pk_point = Curve.basePoint.mul(sk[0..n].*, .big) catch unreachable;
                const pk_bytes = pk_point.toUncompressedSec1();
                @memcpy(pk[0 .. 1 + 2 * n], &pk_bytes);
            },
            else => unreachable,
        }
        return .{ .sk = sk, .pk = pk };
    }

    fn pqDeriveKeyPair(kem: KemId, seed: []const u8, kem_suite_id: *const [5]u8) DerivedKeyPair {
        switch (kem) {
            inline .ml_kem_512,
            .ml_kem_768,
            .ml_kem_1024,
            .mlkem768_x25519,
            .mlkem768_p256,
            .mlkem1024_p384,
            => |tag| {
                const Kem = tag.PqKem();
                const nsk = comptime tag.kemNsk();

                var dk_seed: [max_secret_key_length]u8 = @splat(0);
                xofLabeledDerive(.shake256, seed, "DeriveKeyPair", "", kem_suite_id, dk_seed[0..nsk]);

                var sk: [max_secret_key_length]u8 = @splat(0);
                var pk: [max_public_key_length]u8 = @splat(0);
                @memcpy(sk[0..nsk], dk_seed[0..nsk]);

                const kp = Kem.KeyPair.generateDeterministic(dk_seed[0..nsk].*) catch unreachable;
                const pk_bytes = kp.public_key.toBytes();
                @memcpy(pk[0..pk_bytes.len], &pk_bytes);

                return .{ .sk = sk, .pk = pk };
            },
            else => unreachable,
        }
    }

    fn senderSetupDeterministicCommon(
        self: *const Hpke,
        pk_r: []const u8,
        info: []const u8,
        mode: Mode,
        psk: []const u8,
        psk_id: []const u8,
        sk_e: []const u8,
        sk_s: ?[]const u8,
    ) SetupError!SenderResult {
        if (self.suite.kem.kemFlavor() == .pqkem) {
            if (mode == .auth or mode == .auth_psk) return error.WeakParameters;
            const result = try pqEncapDeterministic(self.suite.kem, pk_r, sk_e);
            return try keySchedule(self.suite, mode, &result.shared_secret, info, psk, psk_id, result.enc[0..result.enc_len]);
        }

        const pk_e = try publicKeyFromSecret(self.suite.kem, sk_e);
        const pk_e_len = self.suite.enc_length;

        var dh: [max_shared_length]u8 = undefined;
        const dh1 = try dhCompute(self.suite.kem, sk_e, pk_r);
        const n = self.suite.kem.nSecret();
        @memcpy(dh[0..n], dh1[0..n]);

        var dh_len: usize = n;
        var kem_ctx_buf: [3 * max_public_key_length]u8 = undefined;
        @memcpy(kem_ctx_buf[0..pk_e_len], pk_e[0..pk_e_len]);
        @memcpy(kem_ctx_buf[pk_e_len..][0..pk_r.len], pk_r);
        var kem_ctx_len: usize = pk_e_len + pk_r.len;

        if (mode == .auth or mode == .auth_psk) {
            const sks = sk_s orelse return error.WeakParameters;
            const dh2 = try dhCompute(self.suite.kem, sks, pk_r);
            @memcpy(dh[n..][0..n], dh2[0..n]);
            dh_len += n;
            const pk_s = try publicKeyFromSecret(self.suite.kem, sks);
            const pk_len = self.suite.public_key_length;
            @memcpy(kem_ctx_buf[kem_ctx_len..][0..pk_len], pk_s[0..pk_len]);
            kem_ctx_len += pk_len;
        }

        const shared_secret_arr = kemExtractAndExpand(self.suite, dh[0..dh_len], kem_ctx_buf[0..kem_ctx_len]);
        return try keySchedule(self.suite, mode, shared_secret_arr[0..n], info, psk, psk_id, pk_e[0..pk_e_len]);
    }

    fn senderSetupCommon(
        self: *const Hpke,
        pk_r: []const u8,
        info: []const u8,
        mode: Mode,
        psk: []const u8,
        psk_id: []const u8,
        sk_s: ?[]const u8,
        io: std.Io,
    ) SetupError!SenderResult {
        if (self.suite.kem.kemFlavor() == .pqkem) {
            if (mode == .auth or mode == .auth_psk) return error.WeakParameters;
            const result = try pqEncap(self.suite.kem, pk_r, io);
            return try keySchedule(self.suite, mode, &result.shared_secret, info, psk, psk_id, result.enc[0..result.enc_len]);
        }

        var seed: [max_secret_key_length]u8 = undefined;
        io.random(seed[0..self.suite.secret_key_length]);
        const kp_e = self.deriveKeyPair(seed[0..self.suite.secret_key_length]);
        return self.senderSetupDeterministicCommon(pk_r, info, mode, psk, psk_id, kp_e.sk[0..self.suite.secret_key_length], sk_s);
    }

    fn recipientSetupCommon(
        self: *const Hpke,
        enc: []const u8,
        sk_r: []const u8,
        info: []const u8,
        mode: Mode,
        psk: []const u8,
        psk_id: []const u8,
        pk_s: ?[]const u8,
    ) SetupError!RecipientContext {
        if (self.suite.kem.kemFlavor() == .pqkem) {
            if (mode == .auth or mode == .auth_psk) return error.WeakParameters;
            const shared_secret = try pqDecap(self.suite.kem, enc, sk_r);
            return try keyScheduleImpl(RecipientContext, self.suite, mode, &shared_secret, info, psk, psk_id);
        }

        const pk_r_arr = try publicKeyFromSecret(self.suite.kem, sk_r);
        const pk_r_len = self.suite.public_key_length;

        var dh: [max_shared_length]u8 = undefined;
        const dh1 = try dhCompute(self.suite.kem, sk_r, enc);
        const n = self.suite.kem.nSecret();
        @memcpy(dh[0..n], dh1[0..n]);

        var dh_len: usize = n;
        var kem_ctx_buf: [3 * max_public_key_length]u8 = undefined;
        @memcpy(kem_ctx_buf[0..enc.len], enc);
        @memcpy(kem_ctx_buf[enc.len..][0..pk_r_len], pk_r_arr[0..pk_r_len]);
        var kem_ctx_len: usize = enc.len + pk_r_len;

        if (mode == .auth or mode == .auth_psk) {
            const pks = pk_s orelse return error.WeakParameters;
            const dh2 = try dhCompute(self.suite.kem, sk_r, pks);
            @memcpy(dh[n..][0..n], dh2[0..n]);
            dh_len += n;
            @memcpy(kem_ctx_buf[kem_ctx_len..][0..pks.len], pks);
            kem_ctx_len += pks.len;
        }

        const shared_secret_arr = kemExtractAndExpand(self.suite, dh[0..dh_len], kem_ctx_buf[0..kem_ctx_len]);
        return try keyScheduleImpl(RecipientContext, self.suite, mode, shared_secret_arr[0..n], info, psk, psk_id);
    }

    fn pqEncap(kem: KemId, pk_r: []const u8, io: std.Io) SetupError!PqEncapResult {
        switch (kem) {
            inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |tag| {
                const Kem = tag.PqKem();
                if (pk_r.len != Kem.PublicKey.encoded_length) return error.InvalidEncoding;
                const pk = Kem.PublicKey.fromBytes(pk_r[0..Kem.PublicKey.encoded_length]) catch return error.InvalidEncoding;
                const result = pk.encaps(io);
                var enc: [max_enc_length]u8 = undefined;
                @memcpy(enc[0..result.ciphertext.len], &result.ciphertext);
                return .{ .shared_secret = result.shared_secret, .enc = enc, .enc_len = result.ciphertext.len };
            },
            inline .mlkem768_x25519, .mlkem768_p256, .mlkem1024_p384 => |tag| {
                const Kem = tag.PqKem();
                if (pk_r.len != Kem.PublicKey.encoded_length) return error.InvalidEncoding;
                const pk = Kem.PublicKey.fromBytes(pk_r[0..Kem.PublicKey.encoded_length]);
                const result = pk.encaps(io) catch return error.InvalidEncoding;
                var enc: [max_enc_length]u8 = undefined;
                @memcpy(enc[0..result.ciphertext.len], &result.ciphertext);
                return .{ .shared_secret = result.shared_secret, .enc = enc, .enc_len = result.ciphertext.len };
            },
            else => return error.InvalidEncoding,
        }
    }

    fn pqEncapDeterministic(kem: KemId, pk_r: []const u8, seed: []const u8) SetupError!PqEncapResult {
        switch (kem) {
            inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |tag| {
                const Kem = tag.PqKem();
                if (pk_r.len != Kem.PublicKey.encoded_length) return error.InvalidEncoding;
                if (seed.len != Kem.encaps_seed_length) return error.InvalidEncoding;
                const pk = Kem.PublicKey.fromBytes(pk_r[0..Kem.PublicKey.encoded_length]) catch return error.InvalidEncoding;
                const result = pk.encapsDeterministic(seed[0..Kem.encaps_seed_length]);
                var enc: [max_enc_length]u8 = undefined;
                @memcpy(enc[0..result.ciphertext.len], &result.ciphertext);
                return .{ .shared_secret = result.shared_secret, .enc = enc, .enc_len = result.ciphertext.len };
            },
            inline .mlkem768_x25519, .mlkem768_p256, .mlkem1024_p384 => |tag| {
                const Kem = tag.PqKem();
                if (pk_r.len != Kem.PublicKey.encoded_length) return error.InvalidEncoding;
                const pk = Kem.PublicKey.fromBytes(pk_r[0..Kem.PublicKey.encoded_length]);
                const result = pk.encapsDeterministic(seed) catch return error.InvalidEncoding;
                var enc: [max_enc_length]u8 = undefined;
                @memcpy(enc[0..result.ciphertext.len], &result.ciphertext);
                return .{ .shared_secret = result.shared_secret, .enc = enc, .enc_len = result.ciphertext.len };
            },
            else => return error.InvalidEncoding,
        }
    }

    fn pqDecap(kem: KemId, enc: []const u8, sk_seed: []const u8) SetupError![32]u8 {
        switch (kem) {
            inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |tag| {
                const Kem = tag.PqKem();
                const nsk = comptime tag.kemNsk();
                const ct_len = comptime @typeInfo(@FieldType(Kem.EncapsulatedSecret, "ciphertext")).array.len;
                if (sk_seed.len != nsk) return error.InvalidEncoding;
                if (enc.len != ct_len) return error.InvalidEncoding;
                const kp = Kem.KeyPair.generateDeterministic(sk_seed[0..nsk].*) catch return error.InvalidEncoding;
                return kp.secret_key.decaps(enc[0..ct_len]) catch return error.InvalidEncoding;
            },
            inline .mlkem768_x25519, .mlkem768_p256, .mlkem1024_p384 => |tag| {
                const Kem = tag.PqKem();
                const nsk = comptime tag.kemNsk();
                const ct_len = comptime @typeInfo(@FieldType(Kem.EncapsulatedSecret, "ciphertext")).array.len;
                if (sk_seed.len != nsk) return error.InvalidEncoding;
                if (enc.len != ct_len) return error.InvalidEncoding;
                const sk = Kem.SecretKey.fromBytes(sk_seed[0..nsk]);
                return sk.decaps(enc[0..ct_len]) catch return error.InvalidEncoding;
            },
            else => return error.InvalidEncoding,
        }
    }

    fn publicKeyFromSecret(kem: KemId, sk: []const u8) SetupError![max_public_key_length]u8 {
        var pk: [max_public_key_length]u8 = undefined;
        switch (kem) {
            .x25519_sha256 => {
                if (sk.len != 32) return error.InvalidEncoding;
                const pk_32 = try crypto.dh.X25519.recoverPublicKey(sk[0..32].*);
                @memcpy(pk[0..32], &pk_32);
            },
            inline .p256_sha256, .p384_sha384 => |tag| {
                const Curve = tag.NistCurve();
                const n = comptime tag.nSecret();
                if (sk.len != n) return error.InvalidEncoding;
                const pk_point = try Curve.basePoint.mul(sk[0..n].*, .big);
                const pk_bytes = pk_point.toUncompressedSec1();
                @memcpy(pk[0 .. 1 + 2 * n], &pk_bytes);
            },
            inline .ml_kem_512,
            .ml_kem_768,
            .ml_kem_1024,
            .mlkem768_x25519,
            .mlkem768_p256,
            .mlkem1024_p384,
            => |tag| {
                const Kem = tag.PqKem();
                const nsk = comptime tag.kemNsk();
                if (sk.len != nsk) return error.InvalidEncoding;
                const kp = Kem.KeyPair.generateDeterministic(sk[0..nsk].*) catch return error.InvalidEncoding;
                const pk_bytes = kp.public_key.toBytes();
                @memcpy(pk[0..pk_bytes.len], &pk_bytes);
            },
        }
        return pk;
    }

    fn dhCompute(kem: KemId, sk: []const u8, pk: []const u8) SetupError![max_shared_length]u8 {
        var dh: [max_shared_length]u8 = undefined;
        switch (kem) {
            .x25519_sha256 => {
                if (sk.len != 32 or pk.len != 32) return error.InvalidEncoding;
                const result = try crypto.dh.X25519.scalarmult(sk[0..32].*, pk[0..32].*);
                @memcpy(dh[0..32], &result);
            },
            inline .p256_sha256, .p384_sha384 => |tag| {
                const Curve = tag.NistCurve();
                const n = comptime tag.nSecret();
                if (sk.len != n) return error.InvalidEncoding;
                if (pk.len != 1 + 2 * n or pk[0] != 0x04) return error.WeakPublicKey;
                const pk_point = try Curve.fromSec1(pk);
                const shared_point = try pk_point.mul(sk[0..n].*, .big);
                const shared_x = shared_point.affineCoordinates().x.toBytes(.big);
                @memcpy(dh[0..n], &shared_x);
            },
            else => return error.InvalidEncoding,
        }
        return dh;
    }

    fn keySchedule(
        suite: CipherSuite,
        mode: Mode,
        shared_secret: []const u8,
        info: []const u8,
        psk: []const u8,
        psk_id: []const u8,
        enc: []const u8,
    ) SetupError!SenderResult {
        var result = SenderResult{
            .enc = @as([max_enc_length]u8, @splat(0)),
            .enc_length = enc.len,
            .ctx = try keyScheduleImpl(SenderContext, suite, mode, shared_secret, info, psk, psk_id),
        };
        @memcpy(result.enc[0..enc.len], enc);
        return result;
    }

    fn verifyPskInputs(mode: Mode, psk: []const u8, psk_id: []const u8) crypto.errors.WeakParametersError!void {
        const got_psk = psk.len > 0;
        const got_psk_id = psk_id.len > 0;
        if (got_psk != got_psk_id) return error.WeakParameters;
        if (got_psk and (mode == .base or mode == .auth)) return error.WeakParameters;
        if (!got_psk and (mode == .psk or mode == .auth_psk)) return error.WeakParameters;
    }

    fn keyScheduleImpl(
        comptime Ctx: type,
        suite: CipherSuite,
        mode: Mode,
        shared_secret: []const u8,
        info: []const u8,
        psk: []const u8,
        psk_id: []const u8,
    ) SetupError!Ctx {
        try verifyPskInputs(mode, psk, psk_id);
        const suite_id = suite.makeSuiteId();

        var ctx = Ctx{
            .suite = suite,
            .key = @as([max_key_length]u8, @splat(0)),
            .base_nonce = @as([max_nonce_length]u8, @splat(0)),
            .sequence = 0,
            .exporter_secret = @as([max_hash_length]u8, @splat(0)),
        };

        if (suite.kdf.kdfFlavor() == .one_stage) {
            oneStageKeySchedule(suite, mode, shared_secret, info, psk, psk_id, &suite_id, ctx.key[0..suite.key_length], ctx.base_nonce[0..suite.nonce_length], ctx.exporter_secret[0..suite.hash_length]);
            return ctx;
        }

        var psk_id_hash: [max_hash_length]u8 = undefined;
        labeledExtract(suite.kdf, "", "psk_id_hash", psk_id, &suite_id, psk_id_hash[0..suite.hash_length]);

        var info_hash: [max_hash_length]u8 = undefined;
        labeledExtract(suite.kdf, "", "info_hash", info, &suite_id, info_hash[0..suite.hash_length]);

        var ks_context: [1 + 2 * max_hash_length]u8 = undefined;
        ks_context[0] = @intFromEnum(mode);
        @memcpy(ks_context[1..][0..suite.hash_length], psk_id_hash[0..suite.hash_length]);
        @memcpy(ks_context[1 + suite.hash_length ..][0..suite.hash_length], info_hash[0..suite.hash_length]);

        var secret: [max_hash_length]u8 = undefined;
        labeledExtract(suite.kdf, shared_secret, "secret", psk, &suite_id, secret[0..suite.hash_length]);

        const ks_ctx = ks_context[0 .. 1 + 2 * suite.hash_length];
        labeledExpand(suite.kdf, secret[0..suite.hash_length], "key", ks_ctx, &suite_id, ctx.key[0..suite.key_length]);
        labeledExpand(suite.kdf, secret[0..suite.hash_length], "base_nonce", ks_ctx, &suite_id, ctx.base_nonce[0..suite.nonce_length]);
        labeledExpand(suite.kdf, secret[0..suite.hash_length], "exp", ks_ctx, &suite_id, ctx.exporter_secret[0..suite.hash_length]);

        return ctx;
    }

    fn oneStageKeySchedule(
        suite: CipherSuite,
        mode: Mode,
        shared_secret: []const u8,
        info: []const u8,
        psk: []const u8,
        psk_id: []const u8,
        suite_id: *const [10]u8,
        key_out: []u8,
        nonce_out: []u8,
        exp_out: []u8,
    ) void {
        const secret_len = key_out.len + nonce_out.len + exp_out.len;
        switch (suite.kdf) {
            inline .shake128, .shake256, .turboshake128, .turboshake256 => |tag| {
                const Xof = tag.Xof();
                var hasher = Xof.init(.{});
                updateLengthPrefixed(&hasher, psk);
                updateLengthPrefixed(&hasher, shared_secret);
                hasher.update("HPKE-v1");
                hasher.update(suite_id);
                const label = "secret";
                hasher.update(&[2]u8{ 0, label.len });
                hasher.update(label);
                var out_len: [2]u8 = undefined;
                mem.writeInt(u16, &out_len, @intCast(secret_len), .big);
                hasher.update(&out_len);
                hasher.update(&[1]u8{@intFromEnum(mode)});
                updateLengthPrefixed(&hasher, psk_id);
                updateLengthPrefixed(&hasher, info);
                hasher.squeeze(key_out);
                hasher.squeeze(nonce_out);
                hasher.squeeze(exp_out);
            },
            else => unreachable,
        }
    }

    fn kemExtractAndExpand(suite: CipherSuite, dh: []const u8, kem_context: []const u8) [max_shared_length]u8 {
        const kem_suite_id = suite.kem.makeKemSuiteId();

        const kem_kdf = suite.kem.kdf().?;
        const kem_hash_len = suite.kem.nSecret();

        var prk: [max_hash_length]u8 = undefined;
        labeledExtract(kem_kdf, "", "eae_prk", dh, &kem_suite_id, prk[0..kem_hash_len]);

        var shared_secret: [max_shared_length]u8 = undefined;
        labeledExpand(kem_kdf, prk[0..kem_hash_len], "shared_secret", kem_context, &kem_suite_id, shared_secret[0..kem_hash_len]);
        return shared_secret;
    }
};

/// Convert a suite ID from wire format (e.g., from a TLS handshake).
pub fn parseSuiteId(bytes: [2]u8) ?CipherSuiteId {
    return std.enums.fromInt(CipherSuiteId, mem.readInt(u16, &bytes, .big));
}

/// Serialize a suite ID to wire format.
pub fn serializeSuiteId(suite: CipherSuiteId) [2]u8 {
    var bytes: [2]u8 = undefined;
    mem.writeInt(u16, &bytes, @intFromEnum(suite), .big);
    return bytes;
}

fn updateLengthPrefixed(hasher: anytype, data: []const u8) void {
    var len_bytes: [2]u8 = undefined;
    mem.writeInt(u16, &len_bytes, @intCast(data.len), .big);
    hasher.update(&len_bytes);
    hasher.update(data);
}

fn xofLabeledDerive(kdf_id: KdfId, ikm: []const u8, comptime label: []const u8, context: []const u8, suite_id: []const u8, out: []u8) void {
    switch (kdf_id) {
        inline .shake128, .shake256, .turboshake128, .turboshake256 => |tag| {
            const Xof = tag.Xof();
            var hasher = Xof.init(.{});
            hasher.update(ikm);
            hasher.update("HPKE-v1");
            hasher.update(suite_id);
            const label_len: [2]u8 = comptime .{
                @intCast(label.len >> 8),
                @intCast(label.len & 0xff),
            };
            hasher.update(&label_len);
            hasher.update(label);
            var out_len: [2]u8 = undefined;
            mem.writeInt(u16, &out_len, @intCast(out.len), .big);
            hasher.update(&out_len);
            hasher.update(context);
            hasher.squeeze(out);
        },
        else => unreachable,
    }
}

fn labeledExtract(kdf_id: KdfId, salt: []const u8, comptime label: []const u8, ikm: []const u8, suite_id: []const u8, out: []u8) void {
    assert(suite_id.len <= 10);
    switch (kdf_id) {
        inline .hkdf_sha256, .hkdf_sha384, .hkdf_sha512 => |tag| hkdfExtractLabeled(tag.Hmac(), salt, label, ikm, suite_id, out),
        else => unreachable,
    }
}

fn labeledExpand(kdf_id: KdfId, prk: []const u8, comptime label: []const u8, info: []const u8, suite_id: []const u8, out: []u8) void {
    assert(suite_id.len <= 10);
    switch (kdf_id) {
        inline .hkdf_sha256, .hkdf_sha384, .hkdf_sha512 => |tag| {
            assert(out.len <= 255 * tag.Hmac().mac_length);
            hkdfExpandLabeled(tag.Hmac(), prk, label, info, suite_id, out);
        },
        else => unreachable,
    }
}

fn hkdfExtractLabeled(comptime Hmac: type, salt: []const u8, comptime label: []const u8, ikm: []const u8, suite_id: []const u8, out: []u8) void {
    assert(out.len == Hmac.mac_length);

    var mac = Hmac.init(salt);
    mac.update("HPKE-v1");
    mac.update(suite_id);
    mac.update(label);
    mac.update(ikm);

    var prk: [Hmac.mac_length]u8 = undefined;
    mac.final(&prk);
    @memcpy(out, &prk);
}

fn hkdfExpandLabeled(comptime Hmac: type, prk: []const u8, comptime label: []const u8, info: []const u8, suite_id: []const u8, out: []u8) void {
    assert(prk.len == Hmac.mac_length);
    assert(out.len <= 255 * Hmac.mac_length);

    var labeled_length: [2]u8 = undefined;
    mem.writeInt(u16, &labeled_length, @intCast(out.len), .big);

    var counter: u8 = 1;
    var out_offset: usize = 0;
    var prev: [Hmac.mac_length]u8 = undefined;
    var first = true;

    while (out_offset < out.len) : (counter += 1) {
        var mac = Hmac.init(prk);
        if (!first) mac.update(&prev);
        mac.update(&labeled_length);
        mac.update("HPKE-v1");
        mac.update(suite_id);
        mac.update(label);
        mac.update(info);
        mac.update(&[_]u8{counter});
        mac.final(&prev);

        const copy_len = @min(Hmac.mac_length, out.len - out_offset);
        @memcpy(out[out_offset..][0..copy_len], prev[0..copy_len]);
        out_offset += copy_len;
        first = false;
    }
}
