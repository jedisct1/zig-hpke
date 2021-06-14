const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;
const meta = std.meta;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const hpke_version = [7]u8{ 'H', 'P', 'K', 'E', '-', 'v', '1' };

pub const Mode = enum(u8) { base = 0x00, psk = 0x01, auth = 0x02, authPsk = 0x03 };

pub const primitives = struct {
    pub const Kem = struct {
        id: u16,
        secret_length: usize,
        public_length: usize,
        shared_length: usize,
        digest_length: usize,
        generateKeyPairFn: fn (allocator: *Allocator) anyerror!KeyPair,
        deterministicKeyPairFn: fn (allocator: *Allocator, secret_key: []const u8) anyerror!KeyPair,
        dhFn: fn (out: []u8, pk: []const u8, sk: []const u8) anyerror!void,

        pub const X25519HkdfSha256 = struct {
            const H = crypto.hash.sha2.Sha256;
            const K = crypto.kdf.hkdf.HkdfSha256;
            pub const id: u16 = 0x0020;
            pub const secret_length: usize = crypto.dh.X25519.secret_length;
            pub const public_length: usize = crypto.dh.X25519.public_length;
            pub const shared_length: usize = crypto.dh.X25519.shared_length;

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

            fn dh(out: []u8, pk: []const u8, sk: []const u8) !void {
                if (pk.len != public_length or sk.len != secret_length or out.len != shared_length) {
                    return error.InvalidParameters;
                }
                const dh_secret = try crypto.dh.X25519.scalarmult(sk[0..secret_length].*, pk[0..public_length].*);
                mem.copy(u8, out, &dh_secret);
            }

            pub const kem = Kem{
                .id = 0x0020,
                .secret_length = secret_length,
                .shared_length = shared_length,
                .public_length = public_length,
                .digest_length = H.digest_length,
                .generateKeyPairFn = generateKeyPair,
                .deterministicKeyPairFn = deterministicKeyPair,
                .dhFn = dh,
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

    pub fn intoPublic(kp: *KeyPair) []const u8 {
        std.crypto.utils.secureZero(u8, kp.secret_key);
        kp.allocator.free(kp.secret_key);
        return kp.public_key;
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

    pub fn labeledExtract(suite: *Suite, suite_id: []const u8, salt: ?[]const u8, label: []const u8, ikm: []const u8) !Prk {
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

    pub fn labeledExpand(suite: *Suite, out: []u8, suite_id: []const u8, prk: Prk, label: []const u8, info: ?[]const u8) !void {
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
            if ((p.key.len == 0) != (psk == null)) {
                return error.PskKeyAndIdMustBeSet;
            }
            if (mode == .base or mode == .auth) {
                return error.PskNotRequired;
            }
        } else if (mode == .auth or mode == .authPsk) {
            return error.PskRequired;
        }
    }

    fn keySchedule(suite: *Suite, mode: Mode, dh_secret: []const u8, info: []const u8, psk: ?Psk) !Context {
        try verifyPskInputs(mode, psk);
        const psk_id: []const u8 = if (psk) |p| p.id else &[_]u8{};
        var psk_id_hash = try suite.labeledExtract(&suite.id.context, null, "psk_id_hash", psk_id);
        defer psk_id_hash.deinit();
        var info_hash = try suite.labeledExtract(&suite.id.context, null, "info_hash", info);
        defer info_hash.deinit();
        var key_schedule_ctx = try ArrayList(u8).initCapacity(&suite.arena.allocator, 4);
        try key_schedule_ctx.append(@enumToInt(mode));
        try key_schedule_ctx.appendSlice(psk_id_hash.bytes);
        try key_schedule_ctx.appendSlice(info_hash.bytes);
        var secret = try suite.labeledExtract(&suite.id.context, dh_secret, "secret", psk_id);
        defer secret.deinit();
        var exporter_secret = try suite.arena.allocator.alloc(u8, suite.kdf.prk_length);
        errdefer suite.arena.allocator.free(exporter_secret);
        try suite.labeledExpand(exporter_secret, &suite.id.context, secret, "exp", key_schedule_ctx.items);
        return Context{
            .allocator = &suite.arena.allocator,
            .suite = suite,
            .exporter_secret = exporter_secret,
        };
    }

    pub fn generateKeyPair(suite: *Suite) !KeyPair {
        return suite.kem.generateKeyPairFn(&suite.arena.allocator);
    }

    pub fn deterministicKeyPair(suite: *Suite, seed: []const u8) !KeyPair {
        var prk = try suite.labeledExtract(&suite.id.kem, null, "dkp_prk", seed);
        defer prk.deinit();
        var secret_key = try suite.arena.allocator.alloc(u8, suite.kem.secret_length);
        errdefer suite.arena.allocator.free(seed);
        try suite.labeledExpand(secret_key, &suite.id.kem, prk, "sk", null);
        return suite.kem.deterministicKeyPairFn(&suite.arena.allocator, secret_key);
    }

    fn extractAndExpandDh(suite: *Suite, dh: []const u8, kem_ctx: []const u8) ![]const u8 {
        const prk = try suite.labeledExtract(&suite.id.kem, null, "eae_prk", dh);
        var dh_secret = try suite.arena.allocator.alloc(u8, suite.kem.digest_length);
        errdefer suite.arena.allocator.free(dh_secret);
        try suite.labeledExpand(dh_secret, &suite.id.kem, prk, "shared_secret", kem_ctx);
        return dh_secret;
    }

    pub const EncapsulatedSecret = struct {
        secret: []const u8,
        encapsulated: []const u8,
    };

    pub fn encap(suite: *Suite, server_pk: []const u8, seed: ?[]const u8) !EncapsulatedSecret {
        var eph_kp = if (seed) |s| try suite.deterministicKeyPair(s) else try suite.generateKeyPair();
        errdefer eph_kp.deinit();
        var dh = try suite.arena.allocator.alloc(u8, suite.kem.shared_length);
        defer suite.arena.allocator.free(dh);
        try suite.kem.dhFn(dh, server_pk, eph_kp.secret_key);
        var kem_ctx = try std.ArrayList(u8).initCapacity(&suite.arena.allocator, eph_kp.public_key.len + server_pk.len);
        defer kem_ctx.deinit();
        kem_ctx.appendSliceAssumeCapacity(eph_kp.public_key);
        kem_ctx.appendSliceAssumeCapacity(server_pk);
        const dh_secret = try suite.extractAndExpandDh(dh, kem_ctx.items);
        return EncapsulatedSecret{
            .secret = dh_secret,
            .encapsulated = eph_kp.intoPublic(),
        };
    }

    pub const Client = struct {
        client_ctx: ClientContext,
        encapsulated_secret: EncapsulatedSecret,
    };

    pub fn createClientDeterministicContext(suite: *Suite, server_pk: []const u8, info: []const u8, psk: ?Psk, seed: ?[]const u8) !Client {
        const encapsulated_secret = try suite.encap(server_pk, seed);
        const mode: Mode = if (psk) |_| .psk else .base;
        const inner_ctx = try suite.keySchedule(mode, encapsulated_secret.secret, info, psk);
        const client_ctx = ClientContext{ .ctx = inner_ctx };
        return Client{
            .client_ctx = client_ctx,
            .encapsulated_secret = encapsulated_secret,
        };
    }
};

const Context = struct {
    allocator: *Allocator,
    suite: *Suite,
    exporter_secret: []const u8,

    fn deinit(ctx: *Context) void {
        ctx.key_schedule_ctx.deinit();
        crypto.utils.secureZero(u8, ctx.exporter_secret);
        ctx.allocator.free(ctx.exporter_secret);
    }
};

pub const ClientContext = struct {
    ctx: Context,
};

pub const ServerContext = struct { ctx: Context };

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
        _ = try std.fmt.hexToBytes(&info, info_hex);

        const server_seed_hex = "29e5fcb544130784b7606e3160d736309d63e044c241d4461a9c9d2e9362f1db";
        var server_seed: [server_seed_hex.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&server_seed, server_seed_hex);
        var server_kp = try suite.deterministicKeyPair(&server_seed);

        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, "ad5e716159a11fdb33527ce98fe39f24ae3449ffb6e93e8911f62c0e9781718a");
        debug.assert(mem.eql(u8, &expected, server_kp.secret_key));
        _ = try std.fmt.hexToBytes(&expected, "46570dfa9f66e17c38e7a081c65cf42bc00e6fed969d326c692748ae866eac6f");
        debug.assert(mem.eql(u8, &expected, server_kp.public_key));

        const client_seed_hex = "3b8ed55f38545e6ea459b6838280b61ff4f5df2a140823373380609fb6c68933";
        var client_seed: [client_seed_hex.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&client_seed, client_seed_hex);
        var client_kp = try suite.deterministicKeyPair(&client_seed);

        const client = try suite.createClientDeterministicContext(server_kp.public_key, &info, null, &client_seed);
        _ = try std.fmt.hexToBytes(&expected, "e7d9aa41faa0481c005d1343b26939c0748a5f6bf1f81fbd1a4e924bf0719149");
        debug.assert(mem.eql(u8, &expected, client.encapsulated_secret.encapsulated));

        _ = try std.fmt.hexToBytes(&expected, "d27ca8c6ce9d8998f3692613c29e5ae0b064234b874a52d65a014eeffed429b9");
        debug.assert(mem.eql(u8, &expected, client.client_ctx.ctx.exporter_secret));
    }
    _ = gpa.deinit();
}
