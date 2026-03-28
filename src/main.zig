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
    xwing = 0x647a, // ML-KEM-768 + X25519 hybrid

    /// Returns the KDF naturally paired with this KEM.
    pub fn kdf(self: KemId) KdfId {
        return switch (self) {
            .x25519_sha256, .p256_sha256 => .hkdf_sha256,
            .p384_sha384 => .hkdf_sha384,
            .xwing => .hkdf_sha256,
        };
    }

    /// Returns the shared secret length in bytes for this KEM.
    pub fn nSecret(self: KemId) u16 {
        return switch (self) {
            .x25519_sha256, .p256_sha256 => 32,
            .p384_sha384 => 48,
            .xwing => 32,
        };
    }

    fn NistCurve(comptime self: KemId) type {
        return switch (self) {
            .p256_sha256 => crypto.ecc.P256,
            .p384_sha384 => crypto.ecc.P384,
            .x25519_sha256, .xwing => @compileError("not a NIST curve"),
        };
    }
};

/// Key Derivation Function identifier.
pub const KdfId = enum(u16) {
    hkdf_sha256 = 1,
    hkdf_sha384 = 2,
    hkdf_sha512 = 3,

    fn Hmac(comptime self: KdfId) type {
        return switch (self) {
            .hkdf_sha256 => crypto.auth.hmac.sha2.HmacSha256,
            .hkdf_sha384 => crypto.auth.hmac.sha2.HmacSha384,
            .hkdf_sha512 => crypto.auth.hmac.sha2.HmacSha512,
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
    xwing_hkdf_sha256_aes128_gcm = 0x0301,

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
        .xwing_hkdf_sha256_aes128_gcm = .{ .kem = .xwing, .kdf = .hkdf_sha256, .aead = .aes128_gcm },
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
const max_enc_length = 1120; // X-Wing ciphertext length (largest)
const max_public_key_length = 1216; // X-Wing public key length (largest)
const max_secret_key_length = 64; // Largest secret key or seed (X-Wing ephemeral seed is 64 bytes)
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
            .xwing => .{
                .pk = 1216, // ML-KEM public (1184) + X25519 public (32)
                .sk = 32, // seed for deterministic generation
                .enc = 1120, // ML-KEM ciphertext (1088) + X25519 ephemeral public (32)
            },
        };

        return .{
            .id = suite_id,
            .kem = components.kem,
            .kdf = components.kdf,
            .aead = components.aead,
            .public_key_length = kem_sizes.pk,
            .secret_key_length = kem_sizes.sk,
            .enc_length = kem_sizes.enc,
            .hash_length = switch (components.kdf) {
                .hkdf_sha256 => 32,
                .hkdf_sha384 => 48,
                .hkdf_sha512 => 64,
            },
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
    labeledExpand(suite.kdf, exporter_secret[0..suite.hash_length], "sec", exporter_context, &suite_id, out);
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

pub const OperationNotSupported = error{OperationNotSupported};
pub const SetupError = crypto.errors.IdentityElementError ||
    crypto.errors.EncodingError ||
    crypto.errors.NonCanonicalError ||
    crypto.errors.NotSquareError ||
    crypto.errors.WeakPublicKeyError ||
    crypto.errors.WeakParametersError ||
    OperationNotSupported;

/// Result of a sender setup: the encapsulated key and the encryption context.
pub const SenderResult = struct {
    enc: [max_enc_length]u8,
    enc_length: usize,
    ctx: SenderContext,
};

/// HPKE (Hybrid Public Key Encryption) per RFC 9180.
pub const Hpke = struct {
    suite: CipherSuite,

    pub fn init(suite_id: CipherSuiteId) Hpke {
        return .{ .suite = CipherSuite.init(suite_id) };
    }

    pub fn publicKeyLength(self: *const Hpke) u16 {
        return self.suite.public_key_length;
    }

    pub fn secretKeyLength(self: *const Hpke) u16 {
        return self.suite.secret_key_length;
    }

    pub fn senderSetup(self: *const Hpke, pk_r: []const u8, info: []const u8, io: std.Io) SetupError!SenderResult {
        return self.senderSetupCore(pk_r, info, .base, "", "", null, io);
    }

    pub fn senderSetupDeterministic(self: *const Hpke, pk_r: []const u8, info: []const u8, sk_e: []const u8) SetupError!SenderResult {
        return self.senderSetupDeterministicCore(pk_r, info, .base, "", "", sk_e, null);
    }

    pub fn senderSetupDeterministicPSK(self: *const Hpke, pk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, sk_e: []const u8) SetupError!SenderResult {
        return self.senderSetupDeterministicCore(pk_r, info, .psk, psk, psk_id, sk_e, null);
    }

    pub fn senderSetupDeterministicAuth(self: *const Hpke, pk_r: []const u8, info: []const u8, sk_s: []const u8, sk_e: []const u8) SetupError!SenderResult {
        return self.senderSetupDeterministicCore(pk_r, info, .auth, "", "", sk_e, sk_s);
    }

    pub fn senderSetupDeterministicAuthPSK(self: *const Hpke, pk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, sk_s: []const u8, sk_e: []const u8) SetupError!SenderResult {
        return self.senderSetupDeterministicCore(pk_r, info, .auth_psk, psk, psk_id, sk_e, sk_s);
    }

    pub fn recipientSetup(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8) SetupError!RecipientContext {
        return self.recipientSetupCore(enc, sk_r, info, .base, "", "", null);
    }

    pub fn senderSetupPSK(self: *const Hpke, pk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, io: std.Io) SetupError!SenderResult {
        return self.senderSetupCore(pk_r, info, .psk, psk, psk_id, null, io);
    }

    pub fn recipientSetupPSK(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8) SetupError!RecipientContext {
        return self.recipientSetupCore(enc, sk_r, info, .psk, psk, psk_id, null);
    }

    pub fn senderSetupAuth(self: *const Hpke, pk_r: []const u8, info: []const u8, sk_s: []const u8, io: std.Io) SetupError!SenderResult {
        return self.senderSetupCore(pk_r, info, .auth, "", "", sk_s, io);
    }

    pub fn recipientSetupAuth(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8, pk_s: []const u8) SetupError!RecipientContext {
        return self.recipientSetupCore(enc, sk_r, info, .auth, "", "", pk_s);
    }

    pub fn senderSetupAuthPSK(self: *const Hpke, pk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, sk_s: []const u8, io: std.Io) SetupError!SenderResult {
        return self.senderSetupCore(pk_r, info, .auth_psk, psk, psk_id, sk_s, io);
    }

    pub fn recipientSetupAuthPSK(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8, pk_s: []const u8) SetupError!RecipientContext {
        return self.recipientSetupCore(enc, sk_r, info, .auth_psk, psk, psk_id, pk_s);
    }

    pub fn deriveKeyPair(self: *const Hpke, seed: []const u8) struct { sk: [max_secret_key_length]u8, pk: [max_public_key_length]u8 } {
        var kem_suite_id: [5]u8 = undefined;
        @memcpy(kem_suite_id[0..3], "KEM");
        mem.writeInt(u16, kem_suite_id[3..5], @intFromEnum(self.suite.kem), .big);

        const kem_kdf = self.suite.kem.kdf();
        const n_secret = self.suite.kem.nSecret();
        var prk: [max_hash_length]u8 = undefined;
        labeledExtract(kem_kdf, "", "dkp_prk", seed, &kem_suite_id, prk[0..n_secret]);

        var sk: [max_secret_key_length]u8 = @splat(0);
        var pk: [max_public_key_length]u8 = @splat(0);

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
            .xwing => {
                // Expand the 32-byte seed to 64 bytes for ML-KEM key generation.
                var seed_mlkem: [64]u8 = undefined;
                @memcpy(seed_mlkem[0..32], seed[0..32]);
                @memset(seed_mlkem[32..64], 0);
                const kp_mlkem = try crypto.kem.ml_kem.MLKem768.KeyPair.generateDeterministic(seed_mlkem);
                const pk_mlkem = kp_mlkem.public_key.toBytes();

                // X25519 key pair from the same original seed (32 bytes).
                var seed_x25519: [32]u8 = undefined;
                @memcpy(&seed_x25519, seed[0..32]);
                const kp_x25519 = crypto.dh.X25519.KeyPair.generateDeterministic(seed_x25519) catch unreachable;
                const pk_x25519 = kp_x25519.public_key;

                @memcpy(sk[0..32], seed);
                @memcpy(pk[0..1184], &pk_mlkem);
                @memcpy(pk[1184..1216], &pk_x25519);
            },
        }
        return .{ .sk = sk, .pk = pk };
    }

    // -----------------------------------------------------------------------------
    // Hybrid KEM helpers (X-Wing)
    // -----------------------------------------------------------------------------

    fn hybridEncaps(pk_r: []const u8, seed: []const u8) !struct { enc: [max_enc_length]u8, shared: [32]u8 } {
        // pk_r is concatenated public key: ML-KEM public (1184) + X25519 public (32)
        if (pk_r.len != 1216) return error.InvalidEncoding;
        if (seed.len != 64) return error.InvalidEncoding;

        const pk_mlkem = pk_r[0..1184];
        const pk_x25519 = pk_r[1184..1216];

        // Extract the first 32 bytes for ML-KEM encapsulation.
        var mlkem_seed: [32]u8 = undefined;
        @memcpy(&mlkem_seed, seed[0..32]);

        const mlkem_pk = try crypto.kem.ml_kem.MLKem768.PublicKey.fromBytes(pk_mlkem);
        const encap = mlkem_pk.encapsDeterministic(&mlkem_seed);
        const ss_mlkem = encap.shared_secret;
        const enc_mlkem = encap.ciphertext;

        // X25519 ephemeral from next 32 bytes of seed.
        var seed_x25519: [32]u8 = undefined;
        @memcpy(&seed_x25519, seed[32..64]);
        const kp_x25519 = try crypto.dh.X25519.KeyPair.generateDeterministic(seed_x25519);
        const pk_e_x25519 = kp_x25519.public_key;
        const ss_x25519 = try crypto.dh.X25519.scalarmult(kp_x25519.secret_key, pk_x25519.*);

        // Combine shared secrets and hash
        var combined: [64]u8 = undefined;
        @memcpy(combined[0..32], &ss_mlkem);
        @memcpy(combined[32..64], &ss_x25519);
        var shared: [32]u8 = undefined;
        crypto.hash.sha3.Sha3_256.hash(&combined, &shared, .{});

        // Build ciphertext: ML-KEM ciphertext (1088) + X25519 ephemeral public (32)
        var enc: [max_enc_length]u8 = undefined;
        @memcpy(enc[0..1088], &enc_mlkem);
        @memcpy(enc[1088..1120], &pk_e_x25519);
        return .{ .enc = enc, .shared = shared };
    }

    fn hybridDecaps(sk_r: []const u8, enc: []const u8) ![32]u8 {
        // sk_r is the seed (32 bytes)
        if (sk_r.len != 32) return error.InvalidEncoding;
        if (enc.len != 1120) return error.InvalidEncoding;

        const enc_mlkem = enc[0..1088];
        const pk_e_x25519 = enc[1088..1120];

        // Reconstruct ML-KEM static key pair from the 32-byte seed, expanded to 64 bytes.
        var seed_mlkem: [64]u8 = undefined;
        @memcpy(seed_mlkem[0..32], sk_r[0..32]);
        @memset(seed_mlkem[32..64], 0);
        const kp_mlkem = try crypto.kem.ml_kem.MLKem768.KeyPair.generateDeterministic(seed_mlkem);
        const ss_mlkem = try kp_mlkem.secret_key.decaps(enc_mlkem);

        // X25519 static key from the same seed.
        var seed_x25519: [32]u8 = undefined;
        @memcpy(&seed_x25519, sk_r[0..32]);
        const kp_x25519 = try crypto.dh.X25519.KeyPair.generateDeterministic(seed_x25519);
        const ss_x25519 = try crypto.dh.X25519.scalarmult(kp_x25519.secret_key, pk_e_x25519.*);

        var combined: [64]u8 = undefined;
        @memcpy(combined[0..32], &ss_mlkem);
        @memcpy(combined[32..64], &ss_x25519);
        var shared: [32]u8 = undefined;
        crypto.hash.sha3.Sha3_256.hash(&combined, &shared, .{});
        return shared;
    }

    fn senderSetupDeterministicCore(self: *const Hpke, pk_r: []const u8, info: []const u8, mode: Mode, psk: []const u8, psk_id: []const u8, sk_e: []const u8, sk_s: ?[]const u8) SetupError!SenderResult {
        // Hybrid KEMs
        if (self.suite.kem == .xwing) {
            if (mode == .auth or mode == .auth_psk) return error.OperationNotSupported;
            const seed = sk_e[0..64];
            const enc_result = try hybridEncaps(pk_r, seed);
            const shared = enc_result.shared;
            const ks = try keyScheduleImpl(SenderContext, self.suite, mode, shared[0..32], info, psk, psk_id);
            var result = SenderResult{
                .enc = @as([max_enc_length]u8, @splat(0)),
                .enc_length = self.suite.enc_length,
                .ctx = ks,
            };
            @memcpy(result.enc[0..self.suite.enc_length], enc_result.enc[0..self.suite.enc_length]);
            return result;
        }

        // DH KEMs
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
        const ks = try keyScheduleImpl(SenderContext, self.suite, mode, shared_secret_arr[0..n], info, psk, psk_id);
        var result = SenderResult{
            .enc = @as([max_enc_length]u8, @splat(0)),
            .enc_length = pk_e_len,
            .ctx = ks,
        };
        @memcpy(result.enc[0..pk_e_len], pk_e[0..pk_e_len]);
        return result;
    }

    fn senderSetupCore(self: *const Hpke, pk_r: []const u8, info: []const u8, mode: Mode, psk: []const u8, psk_id: []const u8, sk_s: ?[]const u8, io: std.Io) SetupError!SenderResult {
        const seed_len = if (self.suite.kem == .xwing) 64 else self.suite.secret_key_length;
        var seed: [max_secret_key_length]u8 = undefined;
        io.random(seed[0..seed_len]);

        if (self.suite.kem == .xwing) {
            // For X-Wing, the full seed is the ephemeral secret.
            return self.senderSetupDeterministicCore(pk_r, info, mode, psk, psk_id, seed[0..64], sk_s);
        }

        const kp_e = self.deriveKeyPair(seed[0..self.suite.secret_key_length]);
        return self.senderSetupDeterministicCore(pk_r, info, mode, psk, psk_id, kp_e.sk[0..self.suite.secret_key_length], sk_s);
    }

    fn recipientSetupCore(self: *const Hpke, enc: []const u8, sk_r: []const u8, info: []const u8, mode: Mode, psk: []const u8, psk_id: []const u8, pk_s: ?[]const u8) SetupError!RecipientContext {
        // Hybrid KEMs
        if (self.suite.kem == .xwing) {
            // Auth modes are not supported X-Wing
            if (mode == .auth or mode == .auth_psk) return error.OperationNotSupported;
            const shared = try hybridDecaps(sk_r, enc);
            return try keyScheduleImpl(RecipientContext, self.suite, mode, shared[0..32], info, psk, psk_id);
        }

        // DH KEMs
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
            .xwing => {
                // Not used for X-Wing (handled separately)
                return error.OperationNotSupported;
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
            .xwing => {
                return error.OperationNotSupported;
            },
        }
        return dh;
    }

    fn verifyPskInputs(mode: Mode, psk: []const u8, psk_id: []const u8) SetupError!void {
        const got_psk = psk.len > 0;
        const got_psk_id = psk_id.len > 0;
        if (got_psk != got_psk_id) return error.WeakParameters;
        if (got_psk and (mode == .base or mode == .auth)) return error.WeakParameters;
        if (!got_psk and (mode == .psk or mode == .auth_psk)) return error.WeakParameters;
    }

    fn keyScheduleImpl(comptime Ctx: type, suite: CipherSuite, mode: Mode, shared_secret: []const u8, info: []const u8, psk: []const u8, psk_id: []const u8) SetupError!Ctx {
        try verifyPskInputs(mode, psk, psk_id);
        const suite_id = suite.makeSuiteId();

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

        var ctx = Ctx{
            .suite = suite,
            .key = @as([max_key_length]u8, @splat(0)),
            .base_nonce = @as([max_nonce_length]u8, @splat(0)),
            .sequence = 0,
            .exporter_secret = @as([max_hash_length]u8, @splat(0)),
        };

        const ks_ctx = ks_context[0 .. 1 + 2 * suite.hash_length];
        labeledExpand(suite.kdf, secret[0..suite.hash_length], "key", ks_ctx, &suite_id, ctx.key[0..suite.key_length]);
        labeledExpand(suite.kdf, secret[0..suite.hash_length], "base_nonce", ks_ctx, &suite_id, ctx.base_nonce[0..suite.nonce_length]);
        labeledExpand(suite.kdf, secret[0..suite.hash_length], "exp", ks_ctx, &suite_id, ctx.exporter_secret[0..suite.hash_length]);

        return ctx;
    }

    fn kemExtractAndExpand(suite: CipherSuite, dh: []const u8, kem_context: []const u8) [max_shared_length]u8 {
        var kem_suite_id: [5]u8 = undefined;
        @memcpy(kem_suite_id[0..3], "KEM");
        mem.writeInt(u16, kem_suite_id[3..5], @intFromEnum(suite.kem), .big);

        const kem_kdf = suite.kem.kdf();
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

fn labeledExtract(kdf_id: KdfId, salt: []const u8, comptime label: []const u8, ikm: []const u8, suite_id: []const u8, out: []u8) void {
    assert(suite_id.len <= 10);
    switch (kdf_id) {
        inline else => |tag| hkdfExtractLabeled(tag.Hmac(), salt, label, ikm, suite_id, out),
    }
}

fn labeledExpand(kdf_id: KdfId, prk: []const u8, comptime label: []const u8, info: []const u8, suite_id: []const u8, out: []u8) void {
    assert(suite_id.len <= 10);
    assert(out.len <= maxExpandLength(kdf_id));
    switch (kdf_id) {
        inline else => |tag| hkdfExpandLabeled(tag.Hmac(), prk, label, info, suite_id, out),
    }
}

fn maxExpandLength(kdf_id: KdfId) usize {
    return switch (kdf_id) {
        inline else => |tag| 255 * tag.Hmac().mac_length,
    };
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
