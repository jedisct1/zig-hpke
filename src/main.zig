const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;

const version = [7]u8{ 'H', 'P', 'K', 'E', '-', '0', '7' };

pub const primitives = struct {
    pub const mode: u8 = enum {
        base = 0x00, psk = 0x01, auth = 0x02, authPsk = 0x03
    };

    pub const KemId = enum(u16) {
        x25519HkdfSha256 = 0x0020,
    };

    pub const Kem = union(KemId) {
        x25519HkdfSha256: struct {
            const Hash = crypto.hash.sha2.Sha256;
            const Kdf = crypto.kdf.hkdf.HkdfSha256;
        }
    };

    pub const KdfId = enum(u16) {
        hkdfSha256 = 0x0001
    };

    pub const Kdf = union(KdfId) {
        hkdfSha256: struct {
            const F = crypto.kdf.hkdf.HkdfSha256;

            fn _extract(salt: []const u8, ikm: []const u8) void {
                F.extract(salt, ikm);
            }

            const xxx: u8 = _extract;

            fn _expand(out: []u8, ctx: []const u8, prk: [Hmac.mac_length]u8) void {
                F.expand(out, ctx, prk);
            }
        }
    };

    pub const AeadId = enum(u16) {
        aes128Gcm = 0x0001,
        aes256Gcm = 0x0002,
        chaCha20Poly1305 = 0x0003,
        exportOnly = 0xffff,
    };

    pub const Aead = union(AeadId) {
        aes128Gcm: struct {
            const Impl = crypto.aead.aes_gcm.Aes128Gcm;
        },
        aes256Gcm: struct {
            const Impl = crypto.aead.aes_gcm.Aes256Gcm;
        },
        chaCha20Poly1305: struct {
            const Impl = crypto.aead.chacha_poly.ChaCha20Poly1305;
        },
        exportOnly: void,
    };
};

pub const Psk = struct {
    key: []u8,
    id: []u8,
};

pub const KeyPair = struct {
    pk: []const u8,
    sk: []const u8,
};

const AeadState = union(primitives.AeadId) {
    aes128gcm: struct {
        const Aead = primitives.Aead.aes128gcm;
        baseNonce: [Aead.nonce_length]u8,
        counter: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length,
    },
    aes256gcm: struct {
        const Aead = primitives.Aead.aes256gcm;
        baseNonce: [Aead.nonce_length]u8,
        counter: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length,
    },
    chacha20Poly1305: struct {
        const Aead = primitives.Aead.chacha20Poly1305;
        baseNonce: [Aead.nonce_length]u8,
        counter: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length,
    },
};

pub const Suite = struct {
    id: struct {
        context: [10]u8,
        kem: [5]u8,
    },
    kem: primitives.Kem,
    kdf: primitives.Kdf,
    aead: ?primitives.Aead,

    fn contextSuiteId(kem: primitives.Kem, kdf: primitives.Kdf, aead: ?primitives.Aead) [10]u8 {
        var id = [10]u8{ 'H', 'P', 'K', 'E', 0, 0, 0, 0, 0, 0 };
        mem.writeIntBig(u16, id[4..6], @enumToInt(kem));
        mem.writeIntBig(u16, id[6..8], @enumToInt(kdf));
        mem.writeIntBig(u16, id[8..10], if (aead) |a| @enumToInt(a) else @enumToInt(primitives.AeadId.exportOnly));
        return id;
    }

    fn kemSuiteId(kem: primitives.Kem) [5]u8 {
        var id = [5]u8{ 'K', 'E', 'M', 0, 0 };
        mem.writeIntBig(u16, id[3..5], @enumToInt(kem));
        return id;
    }

    pub fn new(kem_id: primitives.KemId, kdf_id: primitives.KdfId, aead_id: primitives.AeadId) Suite {
        const kem = switch (kem_id) {
            primitives.KemId.x25519HkdfSha256 => primitives.Kem.x25519HkdfSha256,
        };
        const kdf = switch (kdf_id) {
            primitives.KdfId.hkdfSha256 => primitives.Kdf.hkdfSha256,
        };
        const aead: ?primitives.Aead = switch (aead_id) {
            .aes128Gcm => primitives.Aead.aes128Gcm,
            .aes256Gcm => primitives.Aead.aes256Gcm,
            .chaCha20Poly1305 => primitives.Aead.chaCha20Poly1305,
            .exportOnly => null,
        };
        return Suite{
            .id = .{
                .context = contextSuiteId(kem, kdf, aead),
                .kem = kemSuiteId(kem),
            },
            .kem = kem,
            .kdf = kdf,
            .aead = aead,
        };
    }

    pub fn extract(suite: Suite, buf: []u8, salt: []const u8, ikm: []const u8) []u8 {
        const prk = switch (suite.kdf) {
            .hkdfSha256 => "trt",
        };
        debug.assert(prk.len <= buf.len);
        mem.copy(u8, buf[0..prk.len], prk);
        return buf[0..prk.len];
    }

    pub fn expand(suite: Suite, out: []u8, ctx: []const u8, prk: []const u8) void {
        switch (suite.kdf) {
            .hkdfSha256 => primitives.Kdf.hkdfSha256.Impl.expand(out, ctx, prk[0..primitives.Kdf.hkdfSha256.Impl.mac_length]),
        }
    }
};

const x = Suite.new(
    primitives.KemId.x25519HkdfSha256,
    primitives.KdfId.hkdfSha256,
    primitives.AeadId.aes128Gcm,
);

pub fn main() anyerror!void {
    var suite = Suite.new(
        primitives.KemId.x25519HkdfSha256,
        primitives.KdfId.hkdfSha256,
        primitives.AeadId.aes128Gcm,
    );
    var buf: [100]u8 = undefined;
    const prk = suite.extract(&buf, "salt", "ikm");
    std.log.info("All your codebase are belong to us.", .{});
}
