const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const fmt = std.fmt;
const mem = std.mem;
const meta = std.meta;
const ArrayList = std.ArrayList;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

fn FixedSlice(comptime T: type, comptime max_len: usize) type {
    return struct {
        const Self = @This();
        buffer: [max_len]T,
        len: usize = 0,

        pub fn init(len: usize) !Self {
            if (len > max_len) return error.SliceTooBig;
            var buffer: [max_len]T = undefined;
            return Self{ .buffer = buffer, .len = len };
        }

        pub fn slice(self: *Self) []T {
            return self.buffer[0..self.len];
        }

        pub fn constSlice(self: Self) []const T {
            return self.buffer[0..self.len];
        }

        pub fn resize(self: *Self, len: usize) ![]T {
            if (len > max_len) return error.SliceTooBig;
            self.len = len;
            return self.slice;
        }

        pub fn fromSlice(m: []const T) !Self {
            var fixed_slice = try init(m.len);
            mem.copy(T, fixed_slice.slice(), m);
            return fixed_slice;
        }

        pub fn clone(self: Self) Self {
            return fromSlice(self.constSlice()) catch unreachable;
        }
    };
}

const hpke_version = [7]u8{ 'H', 'P', 'K', 'E', '-', 'v', '1' };

pub const Mode = enum(u8) { base = 0x00, psk = 0x01, auth = 0x02, authPsk = 0x03 };

pub const max_public_key_length: usize = 32;
pub const max_secret_key_length: usize = 32;
pub const max_shared_key_length: usize = 32;
pub const max_prk_length: usize = 32;
pub const max_label_length: usize = 64;
pub const max_info_length: usize = 64;
pub const max_suite_id_length: usize = 10;
pub const max_digest_length: usize = 32;
pub const max_ikm_length: usize = 64;
pub const max_aead_key_length: usize = 32;
pub const max_aead_nonce_length: usize = 12;
pub const max_aead_tag_length: usize = 16;

pub const primitives = struct {
    pub const Kem = struct {
        id: u16,
        secret_length: usize,
        public_length: usize,
        shared_length: usize,
        digest_length: usize,
        generateKeyPairFn: fn () anyerror!KeyPair,
        deterministicKeyPairFn: fn (secret_key: []const u8) anyerror!KeyPair,
        dhFn: fn (out: []u8, pk: []const u8, sk: []const u8) anyerror!void,

        pub const X25519HkdfSha256 = struct {
            const H = crypto.hash.sha2.Sha256;
            const K = crypto.kdf.hkdf.HkdfSha256;
            pub const id: u16 = 0x0020;
            pub const secret_length: usize = crypto.dh.X25519.secret_length;
            pub const public_length: usize = crypto.dh.X25519.public_length;
            pub const shared_length: usize = crypto.dh.X25519.shared_length;

            fn generateKeyPair() !KeyPair {
                const kp = try crypto.dh.X25519.KeyPair.create(null);
                return KeyPair{
                    .public_key = try FixedSlice(u8, max_public_key_length).fromSlice(&kp.public_key),
                    .secret_key = try FixedSlice(u8, max_secret_key_length).fromSlice(&kp.secret_key),
                };
            }

            fn deterministicKeyPair(secret_key: []const u8) !KeyPair {
                debug.assert(secret_key.len == secret_length);
                const public_key = try crypto.dh.X25519.recoverPublicKey(secret_key[0..secret_length].*);
                return KeyPair{
                    .public_key = try FixedSlice(u8, max_public_key_length).fromSlice(&public_key),
                    .secret_key = try FixedSlice(u8, max_secret_key_length).fromSlice(secret_key),
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
        newStateFn: fn (key: []const u8, base_nonce: []const u8) error{ InvalidParameters, SliceTooBig }!State,

        pub const State = struct {
            base_nonce: FixedSlice(u8, max_aead_nonce_length),
            counter: FixedSlice(u8, max_aead_nonce_length),
            key: FixedSlice(u8, max_aead_key_length),
            encryptFn: fn (c: []u8, m: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) void,
            decryptFn: fn (m: []u8, c: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) crypto.errors.AuthenticationError!void,

            fn incrementCounter(counter: []u8) void {
                var i = counter.len;
                var carry: u1 = 1;
                var x: u8 = undefined;
                while (true) {
                    i -= 1;
                    carry = @boolToInt(@addWithOverflow(u8, counter[i], carry, &x));
                    counter[i] = x;
                    if (i == 0) break;
                }
                debug.assert(carry == 0); // Counter overflow
            }

            pub fn nextNonce(state: *State) FixedSlice(u8, max_aead_nonce_length) {
                debug.assert(state.counter.len == state.base_nonce.len);
                var base_nonce = state.base_nonce.clone();
                var nonce = base_nonce.slice();
                var counter = state.counter.slice();
                for (nonce) |*p, i| {
                    p.* ^= counter[i];
                }
                incrementCounter(counter);
                return FixedSlice(u8, max_aead_nonce_length).fromSlice(nonce) catch unreachable;
            }
        };

        pub const Aes128Gcm = struct {
            const A = crypto.aead.aes_gcm.Aes128Gcm;
            pub const id: u16 = 0x0001;

            fn newState(key: []const u8, base_nonce: []const u8) error{ InvalidParameters, SliceTooBig }!State {
                if (key.len != A.key_length or base_nonce.len != A.nonce_length) {
                    return error.InvalidParameters;
                }
                var counter = try FixedSlice(u8, max_aead_nonce_length).init(A.nonce_length);
                mem.set(u8, counter.slice(), 0);
                var state = State{
                    .base_nonce = try FixedSlice(u8, max_aead_nonce_length).fromSlice(base_nonce),
                    .counter = counter,
                    .key = try FixedSlice(u8, max_aead_key_length).fromSlice(key),
                    .encryptFn = encrypt,
                    .decryptFn = decrypt,
                };
                return state;
            }

            fn encrypt(c: []u8, m: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) void {
                A.encrypt(c[0..m.len], c[m.len..][0..A.tag_length], m, ad, nonce[0..A.nonce_length].*, key[0..A.key_length].*);
            }

            fn decrypt(m: []u8, c: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) !void {
                return A.decrypt(m, c[0..m.len], c[m.len..][0..A.tag_length].*, ad, nonce[0..A.nonce_length].*, key[0..A.key_length].*);
            }

            pub const aead = Aead{
                .id = id,
                .key_length = A.key_length,
                .nonce_length = A.nonce_length,
                .tag_length = A.tag_length,
                .newStateFn = newState,
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
    public_key: FixedSlice(u8, max_public_key_length),
    secret_key: FixedSlice(u8, max_secret_key_length),
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

    pub fn init(kem_id: u16, kdf_id: u16, aead_id: u16) !Suite {
        const kem = switch (kem_id) {
            primitives.Kem.X25519HkdfSha256.id => primitives.Kem.X25519HkdfSha256.kem,
            else => unreachable,
        };
        const kdf = try primitives.Kdf.fromId(kdf_id);
        const aead = try primitives.Aead.fromId(aead_id);
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

    pub fn extract(suite: Suite, prk: []u8, salt: ?[]const u8, ikm: []const u8) void {
        const prk_length = suite.kdf.prk_length;
        debug.assert(prk.len == prk_length);
        suite.kdf.extract(prk, salt orelse "", ikm);
    }

    pub fn expand(suite: Suite, out: []u8, ctx: []const u8, prk: []const u8) void {
        suite.kdf.expand(out, ctx, prk);
    }

    pub const Prk = FixedSlice(u8, max_prk_length);

    pub fn labeledExtract(suite: *Suite, suite_id: []const u8, salt: ?[]const u8, label: []const u8, ikm: []const u8) !Prk {
        var buffer: [hpke_version.len + max_suite_id_length + max_label_length + max_ikm_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var secret = try ArrayList(u8).initCapacity(&alloc.allocator, alloc.buffer.len);
        try secret.appendSlice(&hpke_version);
        try secret.appendSlice(suite_id);
        try secret.appendSlice(label);
        try secret.appendSlice(ikm);
        var prk = try Prk.init(suite.kdf.prk_length);
        suite.extract(prk.slice(), salt, secret.items);

        return prk;
    }

    pub fn labeledExpand(suite: *Suite, out: []u8, suite_id: []const u8, prk: Prk, label: []const u8, info: ?[]const u8) !void {
        var out_length = [_]u8{ 0, 0 };
        mem.writeIntBig(u16, &out_length, @intCast(u16, out.len));
        var buffer: [out_length.len + hpke_version.len + max_suite_id_length + max_label_length + max_info_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var labeled_info = try ArrayList(u8).initCapacity(&alloc.allocator, alloc.buffer.len);
        try labeled_info.appendSlice(&out_length);
        try labeled_info.appendSlice(&hpke_version);
        try labeled_info.appendSlice(suite_id);
        try labeled_info.appendSlice(label);
        if (info) |i| try labeled_info.appendSlice(i);
        suite.expand(out, labeled_info.items, prk.constSlice());
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
        var info_hash = try suite.labeledExtract(&suite.id.context, null, "info_hash", info);

        var buffer: [1 + max_prk_length + max_prk_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var key_schedule_ctx = try ArrayList(u8).initCapacity(&alloc.allocator, alloc.buffer.len);
        try key_schedule_ctx.append(@enumToInt(mode));
        try key_schedule_ctx.appendSlice(psk_id_hash.constSlice());
        try key_schedule_ctx.appendSlice(info_hash.constSlice());
        var secret = try suite.labeledExtract(&suite.id.context, dh_secret, "secret", psk_id);
        var exporter_secret = try FixedSlice(u8, max_prk_length).init(suite.kdf.prk_length);
        try suite.labeledExpand(exporter_secret.slice(), &suite.id.context, secret, "exp", key_schedule_ctx.items);

        var outbound_state = if (suite.aead) |aead| blk: {
            var outbound_key = try FixedSlice(u8, max_aead_key_length).init(aead.key_length);
            try suite.labeledExpand(outbound_key.slice(), &suite.id.context, secret, "key", key_schedule_ctx.items);
            var outbound_base_nonce = try FixedSlice(u8, max_aead_nonce_length).init(aead.nonce_length);
            try suite.labeledExpand(outbound_base_nonce.slice(), &suite.id.context, secret, "base_nonce", key_schedule_ctx.items);
            break :blk try aead.newStateFn(outbound_key.constSlice(), outbound_base_nonce.constSlice());
        } else null;

        return Context{
            .suite = suite,
            .exporter_secret = exporter_secret,
            .outbound_state = outbound_state,
        };
    }

    pub fn generateKeyPair(suite: *Suite) !KeyPair {
        return suite.kem.generateKeyPairFn();
    }

    pub fn deterministicKeyPair(suite: *Suite, seed: []const u8) !KeyPair {
        var prk = try suite.labeledExtract(&suite.id.kem, null, "dkp_prk", seed);
        var secret_key = try FixedSlice(u8, max_secret_key_length).init(suite.kem.secret_length);
        try suite.labeledExpand(secret_key.slice(), &suite.id.kem, prk, "sk", null);
        return suite.kem.deterministicKeyPairFn(secret_key.constSlice());
    }

    fn extractAndExpandDh(suite: *Suite, dh: []const u8, kem_ctx: []const u8) !FixedSlice(u8, max_shared_key_length) {
        const prk = try suite.labeledExtract(&suite.id.kem, null, "eae_prk", dh);
        var dh_secret = try FixedSlice(u8, max_digest_length).init(suite.kem.shared_length);
        try suite.labeledExpand(dh_secret.slice(), &suite.id.kem, prk, "shared_secret", kem_ctx);
        return dh_secret;
    }

    pub const EncapsulatedSecret = struct {
        secret: FixedSlice(u8, max_digest_length),
        encapsulated: FixedSlice(u8, max_public_key_length),
    };

    pub fn encap(suite: *Suite, server_pk: []const u8, seed: ?[]const u8) !EncapsulatedSecret {
        var eph_kp = if (seed) |s| try suite.deterministicKeyPair(s) else try suite.generateKeyPair();
        var dh = try FixedSlice(u8, max_shared_key_length).init(suite.kem.shared_length);
        try suite.kem.dhFn(dh.slice(), server_pk, eph_kp.secret_key.slice());
        var buffer: [max_public_key_length + max_public_key_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var kem_ctx = try ArrayList(u8).initCapacity(&alloc.allocator, alloc.buffer.len);
        try kem_ctx.appendSlice(eph_kp.public_key.slice());
        try kem_ctx.appendSlice(server_pk);
        const dh_secret = try suite.extractAndExpandDh(dh.constSlice(), kem_ctx.items);
        return EncapsulatedSecret{
            .secret = dh_secret,
            .encapsulated = eph_kp.public_key,
        };
    }

    pub fn decap(suite: *Suite, eph_pk: []const u8, server_kp: KeyPair) !FixedSlice(u8, max_shared_key_length) {
        var dh = try FixedSlice(u8, max_shared_key_length).init(suite.kem.shared_length);
        try suite.kem.dhFn(dh.slice(), eph_pk, server_kp.secret_key.constSlice());
        var buffer: [max_public_key_length + max_public_key_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var kem_ctx = try ArrayList(u8).initCapacity(&alloc.allocator, alloc.buffer.len);
        try kem_ctx.appendSlice(eph_pk);
        try kem_ctx.appendSlice(server_kp.public_key.constSlice());
        return suite.extractAndExpandDh(dh.constSlice(), kem_ctx.items);
    }

    pub const ClientContextAndEncapsulatedSecret = struct {
        client_ctx: ClientContext,
        encapsulated_secret: EncapsulatedSecret,
    };

    pub fn createClientContext(suite: *Suite, server_pk: []const u8, info: []const u8, psk: ?Psk, seed: ?[]const u8) !ClientContextAndEncapsulatedSecret {
        const encapsulated_secret = try suite.encap(server_pk, seed);
        const mode: Mode = if (psk) |_| .psk else .base;
        const inner_ctx = try suite.keySchedule(mode, encapsulated_secret.secret.constSlice(), info, psk);
        const client_ctx = ClientContext{ .ctx = inner_ctx };
        return ClientContextAndEncapsulatedSecret{
            .client_ctx = client_ctx,
            .encapsulated_secret = encapsulated_secret,
        };
    }

    pub fn createServerContext(suite: *Suite, encapsulated_secret: []const u8, server_kp: KeyPair, info: []const u8, psk: ?Psk) !ServerContext {
        const dh_secret = try suite.decap(encapsulated_secret, server_kp);
        const mode: Mode = if (psk) |_| .psk else .base;
        const inner_ctx = try suite.keySchedule(mode, dh_secret.constSlice(), info, psk);
        return ServerContext{ .ctx = inner_ctx };
    }
};

const Context = struct {
    suite: *Suite,
    exporter_secret: FixedSlice(u8, max_prk_length),
    outbound_state: ?primitives.Aead.State,

    fn exportSecret(ctx: Context, out: []u8, exporter_context: []const u8) !void {
        try ctx.suite.labeledExpand(out, &ctx.suite.id.context, ctx.exporter_secret, "sec", exporter_context);
    }
};

pub const ClientContext = struct {
    ctx: Context,

    pub fn encryptToServer(client_context: *ClientContext, ciphertext: []u8, message: []const u8, ad: []const u8) void {
        const required_ciphertext_length = client_context.ctx.suite.aead.?.tag_length + message.len;
        debug.assert(ciphertext.len == required_ciphertext_length);
        var state = &client_context.ctx.outbound_state.?;
        const nonce = state.nextNonce();
        state.encryptFn(ciphertext, message, ad, nonce.constSlice(), state.key.constSlice());
    }

    pub fn exporterSecret(client_context: ClientContext) FixedSlice(u8, max_prk_length) {
        return client_context.ctx.exporter_secret;
    }

    pub fn exportSecret(client_context: ClientContext, out: []u8, context: []const u8) !void {
        try client_context.ctx.exportSecret(out, context);
    }
};

pub const ServerContext = struct {
    ctx: Context,

    pub fn decryptFromClient(server_context: *ServerContext, message: []u8, ciphertext: []const u8, ad: []const u8) !void {
        const required_ciphertext_length = server_context.ctx.suite.aead.?.tag_length + message.len;
        debug.assert(ciphertext.len == required_ciphertext_length);
        var state = &server_context.ctx.outbound_state.?;
        const nonce = state.nextNonce();
        try state.decryptFn(message, ciphertext, ad, nonce.constSlice(), state.key.constSlice());
    }

    pub fn exporterSecret(server_context: ServerContext) FixedSlice(u8, max_prk_length) {
        return server_context.ctx.exporter_secret;
    }

    pub fn exportSecret(server_context: ServerContext, out: []u8, context: []const u8) !void {
        try server_context.ctx.exportSecret(out, context);
    }
};

pub fn main() anyerror!void {
    var suite = try Suite.init(
        primitives.Kem.X25519HkdfSha256.id,
        primitives.Kdf.HkdfSha256.id,
        primitives.Aead.Aes128Gcm.id,
    );

    var info_hex = "4f6465206f6e2061204772656369616e2055726e";
    var info: [info_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&info, info_hex);

    const server_seed_hex = "29e5fcb544130784b7606e3160d736309d63e044c241d4461a9c9d2e9362f1db";
    var server_seed: [server_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&server_seed, server_seed_hex);
    var server_kp = try suite.deterministicKeyPair(&server_seed);

    var expected: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "ad5e716159a11fdb33527ce98fe39f24ae3449ffb6e93e8911f62c0e9781718a");
    debug.assert(mem.eql(u8, &expected, server_kp.secret_key.slice()));
    _ = try fmt.hexToBytes(&expected, "46570dfa9f66e17c38e7a081c65cf42bc00e6fed969d326c692748ae866eac6f");
    debug.assert(mem.eql(u8, &expected, server_kp.public_key.slice()));

    const client_seed_hex = "3b8ed55f38545e6ea459b6838280b61ff4f5df2a140823373380609fb6c68933";
    var client_seed: [client_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&client_seed, client_seed_hex);
    var client_kp = try suite.deterministicKeyPair(&client_seed);

    var client_ctx_and_encapsulated_secret = try suite.createClientContext(server_kp.public_key.slice(), &info, null, &client_seed);
    const encapsulated_secret = client_ctx_and_encapsulated_secret.encapsulated_secret;
    _ = try fmt.hexToBytes(&expected, "e7d9aa41faa0481c005d1343b26939c0748a5f6bf1f81fbd1a4e924bf0719149");
    debug.assert(mem.eql(u8, &expected, encapsulated_secret.encapsulated.constSlice()));

    var client_ctx = client_ctx_and_encapsulated_secret.client_ctx;
    _ = try fmt.hexToBytes(&expected, "d27ca8c6ce9d8998f3692613c29e5ae0b064234b874a52d65a014eeffed429b9");
    debug.assert(mem.eql(u8, &expected, client_ctx.exporterSecret().constSlice()));

    var server_ctx = try suite.createServerContext(encapsulated_secret.encapsulated.constSlice(), server_kp, &info, null);

    const message = "message";
    const ad = "ad";
    var ciphertext: [max_aead_tag_length + message.len]u8 = undefined;
    client_ctx.encryptToServer(&ciphertext, message, ad);
    _ = try fmt.hexToBytes(&expected, "dc54a1124854e041089e52066349a238380aaf6bf98a4c");
    debug.assert(mem.eql(u8, expected[0..ciphertext.len], &ciphertext));

    var message2: [message.len]u8 = undefined;
    try server_ctx.decryptFromClient(&message2, &ciphertext, ad);
    debug.assert(mem.eql(u8, message[0..], message2[0..]));

    client_ctx.encryptToServer(&ciphertext, message, ad);
    _ = try fmt.hexToBytes(&expected, "37fbdf5f21e77f15291212fe94579054f56eaf5e78f2b5");
    debug.assert(mem.eql(u8, expected[0..ciphertext.len], &ciphertext));

    try server_ctx.decryptFromClient(&message2, &ciphertext, ad);
    debug.assert(mem.eql(u8, message[0..], message2[0..]));

    _ = try fmt.hexToBytes(&expected, "ede5198c19b2591389fc7cea");
    const base_nonce = client_ctx.ctx.outbound_state.?.base_nonce.constSlice();
    debug.assert(mem.eql(u8, base_nonce, expected[0..base_nonce.len]));

    var exported_secret: [expected.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "4ab2fe1958f433ebdd2e6302a81a5a7ca91f2ecf2188658524d681be7a9f8e45");
    try client_ctx.exportSecret(&exported_secret, "exported secret");
    debug.assert(mem.eql(u8, &expected, &exported_secret));
    try server_ctx.exportSecret(&exported_secret, "exported secret");
    debug.assert(mem.eql(u8, &expected, &exported_secret));
}
