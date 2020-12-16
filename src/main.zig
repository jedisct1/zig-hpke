const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;
const meta = std.meta;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const hpke_version = [7]u8{ 'H', 'P', 'K', 'E', '-', 'v', '1' };

pub const Mode: u8 = enum {
    base = 0x00, psk = 0x01, auth = 0x02, authPsk = 0x03
};

pub const primitives = struct {
    pub const Kem = struct {
        id: u16,
        secret_length: usize,
        generateKeyPairFn: fn (allocator: *Allocator) anyerror!KeyPair,
        deterministicKeyPairFn: fn (allocator: *Allocator, secret_key: []const u8) anyerror!KeyPair,

        pub const X25519HkdfSha256 = struct {
            const H = crypto.hash.sha2.Sha256;
            const K = crypto.kdf.hkdf.HkdfSha256;
            pub const id: u16 = 0x0020;
            pub const secret_length: usize = crypto.dh.X25519.secret_length;

            fn generateKeyPair(allocator: *Allocator) !KeyPair {
                const kp = try crypto.dh.X25519.KeyPair.create(null);
                return KeyPair{
                    .allocator = allocator,
                    .public_key = try allocator.dupe(u8, &kp.public_key),
                    .secret_key = try allocator.dupe(u8, &kp.secret_key),
                };
            }

            fn deterministicKeyPair(allocator: *Allocator, secret_key: []const u8) !KeyPair {
                debug.assert(secret_key.len == secret_length);
                const public_key = try crypto.dh.X25519.recoverPublicKey(secret_key[0..secret_length].*);
                return KeyPair{
                    .allocator = allocator,
                    .public_key = try allocator.dupe(u8, &public_key),
                    .secret_key = try allocator.dupe(u8, secret_key),
                };
            }

            pub const kem = Kem{
                .id = 0x0020,
                .secret_length = secret_length,
                .generateKeyPairFn = generateKeyPair,
                .deterministicKeyPairFn = deterministicKeyPair,
            };
        };

        pub fn fromId(id: u16) !Kem {
            return switch (id) {
                X25519HkdfSha256.id => X25519HkdfSha256.kem,
                else => error.UnsupportedKem,
            };
        }
    };

    pub const Kdf = struct {
        id: u16,
        prk_length: usize,
        extract: fn (out: []u8, salt: []const u8, ikm: []const u8) void,
        expand: fn (out: []u8, ctx: []const u8, prk: []const u8) void,

        pub const HkdfSha256 = struct {
            const M = crypto.auth.hmac.sha2.HmacSha256;
            const F = crypto.kdf.hkdf.Hkdf(M);
            pub const prk_length = M.mac_length;
            pub const id: u16 = 0x0001;

            fn extract(out: []u8, salt: []const u8, ikm: []const u8) void {
                const prk = F.extract(salt, ikm);
                debug.assert(prk.len == out.len);
                mem.copy(u8, out, &prk);
            }

            fn expand(out: []u8, ctx: []const u8, prk: []const u8) void {
                debug.assert(prk.len == prk_length);
                F.expand(out, ctx, prk[0..prk_length].*);
            }

            pub const kdf = Kdf{
                .id = id,
                .prk_length = prk_length,
                .extract = extract,
                .expand = expand,
            };
        };

        pub fn fromId(id: u16) !Kdf {
            return switch (id) {
                HkdfSha256.id => HkdfSha256.kdf,
                else => error.UnsupportedKdf,
            };
        }
    };

    pub const Aead = struct {
        id: u16,
        key_length: usize,
        nonce_length: usize,
        tag_length: usize,

        pub const State = struct {
            aead: Aead,
            key: [32]u8 = undefined,
            base_nonce: [32]u8 = undefined,
            counter: [32]u8 = [_]u8{0} ** 32,
            encryptFn: fn (c: []u8, m: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) void,
            decryptFn: fn (m: []u8, c: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) !void,
        };

        pub const Aes128Gcm = struct {
            const A = crypto.aead.aes_gcm.Aes128Gcm;
            pub const id: u16 = 0x0001;

            fn newState(key: []const u8, base_nonce: []const u8) !State {
                debug.assert(key.len == A.key_length);
                debug.assert(base_nonce.len == A.nonce_length);
                var state = State{
                    .aead = aead,
                    .encryptFn = encrypt,
                    .decryptFn = decrypt,
                };
                comptime debug.assert(state.key.len >= A.key_length);
                comptime debug.assert(state.base_nonce.len >= A.nonce_length);
                mem.copy(u8, state.key, key);
                mem.copy(u8, state.base_nonce, base_nonce);
                return state;
            }

            fn encrypt(c: []u8, m: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) void {
                A.encrypt(c[0..m.len], c[m.len..][0..A.tag_length], m, ad, nonce[0..A.nonce_length], key[0..A.key_length]);
            }

            fn decrypt(m: []u8, c: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) !void {
                A.decrypt(m, c[0..m.len], c[m.len..][0..A.tag_length], ad, nonce[0..A.nonce_length], key[0..A.key_length]);
            }

            pub const aead = Aead{
                .id = id,
                .key_length = A.key_length,
                .nonce_length = A.nonce_length,
                .tag_length = A.tag_length,
            };
        };

        pub const ExportOnly = struct {
            pub const id: u16 = 0xffff;
        };

        pub fn fromId(id: u16) !?Aead {
            return switch (id) {
                Aes128Gcm.id => Aes128Gcm.aead,
                ExportOnly.id => null,
                else => error.UnsupportedKdf,
            };
        }
    };
};

pub const Psk = struct {
    key: []u8,
    id: []u8,
};

pub const KeyPair = struct {
    allocator: *Allocator,
    public_key: []u8,
    secret_key: []u8,

    pub fn deinit(kp: *KeyPair) void {
        kp.allocator.free(kp.public_key);
        kp.allocator.free(kp.secret_key);
    }
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
    arena: ArenaAllocator,

    id: struct {
        context: [10]u8,
        kem: [5]u8,
    },
    kem: primitives.Kem,
    kdf: primitives.Kdf,
    aead: ?primitives.Aead,

    fn contextSuiteId(kem: primitives.Kem, kdf: primitives.Kdf, aead: ?primitives.Aead) [10]u8 {
        var id = [10]u8{ 'H', 'P', 'K', 'E', 0, 0, 0, 0, 0, 0 };
        mem.writeIntBig(u16, id[4..6], kem.id);
        mem.writeIntBig(u16, id[6..8], kdf.id);
        mem.writeIntBig(u16, id[8..10], if (aead) |a| a.id else primitives.Aead.ExportOnly.id);
        return id;
    }

    fn kemSuiteId(kem: primitives.Kem) [5]u8 {
        var id = [5]u8{ 'K', 'E', 'M', 0, 0 };
        mem.writeIntBig(u16, id[3..5], kem.id);
        return id;
    }

    fn deinit(suite: *Suite) void {
        suite.arena.deinit();
    }

    pub fn init(allocator: *Allocator, kem_id: u16, kdf_id: u16, aead_id: u16) !Suite {
        var arena = ArenaAllocator.init(allocator);
        const kem = switch (kem_id) {
            primitives.Kem.X25519HkdfSha256.id => primitives.Kem.X25519HkdfSha256.kem,
            else => unreachable,
        };
        const kdf = try primitives.Kdf.fromId(kdf_id);
        const aead = try primitives.Aead.fromId(aead_id);
        return Suite{
            .arena = arena,
            .id = .{
                .context = contextSuiteId(kem, kdf, aead),
                .kem = kemSuiteId(kem),
            },
            .kem = kem,
            .kdf = kdf,
            .aead = aead,
        };
    }

    pub fn extract(suite: Suite, prk: []u8, salt: ?[]const u8, ikm: []const u8) void {
        const prk_length = suite.kdf.prk_length;
        debug.assert(prk.len == prk_length);
        suite.kdf.extract(prk, salt orelse "", ikm);
    }

    pub fn expand(suite: Suite, out: []u8, ctx: []const u8, prk: []const u8) void {
        suite.kdf.expand(out, ctx, prk);
    }

    pub const Prk = struct {
        allocator: *Allocator,
        bytes: []u8,

        pub fn init(allocator: *Allocator, length: usize) !Prk {
            return Prk{
                .allocator = allocator,
                .bytes = try allocator.alloc(u8, length),
            };
        }

        pub fn deinit(prk: *Prk) void {
            prk.allocator.free(prk.bytes);
        }
    };

    fn labeledExtract(suite: *Suite, suite_id: []const u8, salt: ?[]const u8, label: []const u8, ikm: []const u8) !Prk {
        var secret = try ArrayList(u8).initCapacity(&suite.arena.allocator, hpke_version.len + suite_id.len + label.len + ikm.len);
        errdefer secret.deinit();
        try secret.appendSlice(&hpke_version);
        try secret.appendSlice(suite_id);
        try secret.appendSlice(label);
        try secret.appendSlice(ikm);
        var prk = try Prk.init(&suite.arena.allocator, suite.kdf.prk_length);
        suite.extract(prk.bytes, salt, secret.items);

        return prk;
    }

    fn labeledExpand(suite: *Suite, out: []u8, prk: *Prk, suite_id: []const u8, label: []const u8, info: ?[]const u8) !void {
        var out_length = [_]u8{ 0, 0 };
        mem.writeIntBig(u16, &out_length, @intCast(u16, out.len));
        var labeled_info = try ArrayList(u8).initCapacity(prk.allocator, out_length.len + hpke_version.len + suite_id.len + label.len + if (info) |i| i.len else 0);
        defer labeled_info.deinit();
        try labeled_info.appendSlice(&out_length);
        try labeled_info.appendSlice(&hpke_version);
        try labeled_info.appendSlice(suite_id);
        try labeled_info.appendSlice(label);
        if (info) |i| try labeled_info.appendSlice(i);
        suite.expand(out, labeled_info.items, prk.bytes);
    }

    fn verifyPskInputs(mode: Mode, psk: ?Psk) !void {
        if (psk) |p| {
            if ((p.key.len == 0) != (psk.id.len == 0)) {
                return error.PskKeyAndIdMustBeSet;
            }
            if (mode == .base or mode == .auth) {
                return error.PskNotRequired;
            }
        } else if (mode == .auth or mode == .authPsk) {
            return error.PskRequired;
        }
    }

    fn keySchedule(suite: *const Suite, mode: Mode, dh_secret: []const u8, info: []const u8, psk: ?Psk) !Context {
        try verifyPskInputs(mode, psk);
        var psk_id_hash = try suite.labeledExtract(suite.id.context, null, "psk_id_hash", if (psk) |p| p.id else []u8{});
        defer suite.arena.allocator.free(psk_id_hash);
        var info_hash = try suite.labeledExtract(suite.id.context, null, "info_hash", info);
        defer suite.arena.allocator.free(info_hash);
        var key_schedule_context = try ArrayList(u8).initCapacity(&suite.arena.allocator, 4);
        try key_schedule_context.append(mode);
        try key_schedule_context.appendSlice(psk_id_hash);
        try key_schedule_context.appendSlice(info_hash);
        var secret = suite.labeledExtract(suite.id.context, dh_secret, "secret", if (psk) |p| p.key else []u8{});
        defer suite.arena.allocator.free(secret);
    }

    pub fn generateKeyPair(suite: *Suite) !KeyPair {
        return suite.kem.generateKeyPairFn(&suite.arena.allocator);
    }

    pub fn deterministicKeyPair(suite: *Suite, seed: []const u8) !KeyPair {
        var prk = try suite.labeledExtract(&suite.id.kem, null, "dkp_prk", seed);
        defer prk.deinit();
        var secret_key = try suite.arena.allocator.alloc(u8, suite.kem.secret_length);
        errdefer suite.arena.allocator.free(seed);
        try suite.labeledExpand(secret_key, &prk, &suite.id.kem, "sk", null);
        return suite.kem.deterministicKeyPairFn(&suite.arena.allocator, secret_key);
    }
};

const Context = struct {
    allocator: *Allocator,
    suite: *Suite,
    key_schedule_context: ArrayList(u8),
    secret: []u8,

    fn deinit(ctx: *Context) void {
        ctx.key_schedule_context.deinit();
        crypto.utils.secureZero(u8, ctx.secret);
        ctx.allocator.free(ctx.secret);
    }
};

pub const ClientContext = struct {
    ctx: Context
};

pub const ServerContext = struct {
    ctx: Context
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    {
        var suite = try Suite.init(
            &gpa.allocator,
            primitives.Kem.X25519HkdfSha256.id,
            primitives.Kdf.HkdfSha256.id,
            primitives.Aead.Aes128Gcm.id,
        );
        defer suite.deinit();

        var info_hex = "4f6465206f6e2061204772656369616e2055726e";
        var info: [info_hex.len / 2]u8 = undefined;
        try std.fmt.hexToBytes(&info, info_hex);

        const server_seed_hex = "6d9014e4609687b0a3670a22f2a14eac5ae6ad8c0beb62fb3ecb13dc8ebf5e06";
        var server_seed: [server_seed_hex.len / 2]u8 = undefined;
        try std.fmt.hexToBytes(&server_seed, server_seed_hex);
        var server_kp = try suite.deterministicKeyPair(&server_seed);

        const client_seed_hex = "6305de86b3cec022fae6f2f2d2951f0f90c8662112124fd62f17e0a99bdbd08e";
        var client_seed: [client_seed_hex.len / 2]u8 = undefined;
        try std.fmt.hexToBytes(&client_seed, client_seed_hex);
        var client_kp = try suite.deterministicKeyPair(&client_seed);

        std.log.info("All your codebase are belong to us. {x} {x}\n", .{ client_kp.secret_key, client_kp.public_key });
    }
    _ = gpa.deinit();
}
