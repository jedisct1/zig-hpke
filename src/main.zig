const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;
const meta = std.meta;
const ArrayList = std.ArrayList;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
const BoundedArray = std.BoundedArray;

const hpke_version = [7]u8{ 'H', 'P', 'K', 'E', '-', 'v', '1' };

/// HPKE mode
pub const Mode = enum(u8) { base = 0x00, psk = 0x01, auth = 0x02, authPsk = 0x03 };

/// Maximum length of a public key in bytes
pub const max_public_key_length: usize = 32;
/// Maximum length of a secret key in bytes
pub const max_secret_key_length: usize = 32;
/// Maximum length of a shared key in bytes
pub const max_shared_key_length: usize = 32;
/// Maximum length of a PRK in bytes
pub const max_prk_length: usize = 32;
/// Maximum length of a label in bytes
pub const max_label_length: usize = 128;
/// Maximum length of an info string in bytes
pub const max_info_length: usize = 1024;
/// Maximum length of a suite ID
pub const max_suite_id_length: usize = 10;
/// Maximum length of a hash function
pub const max_digest_length: usize = 32;
/// Maximum length of input keying material
pub const max_ikm_length: usize = 64;
/// Maximum length of an AEAD key
pub const max_aead_key_length: usize = 32;
/// Maximum length of an AEAD nonce
pub const max_aead_nonce_length: usize = 12;
/// Maximum length of an AEAD tag
pub const max_aead_tag_length: usize = 16;

/// HPKE primitives
pub const primitives = struct {
    /// Key exchange mechanisms
    pub const Kem = struct {
        id: u16,
        secret_length: usize,
        public_length: usize,
        shared_length: usize,
        digest_length: usize,
        generateKeyPairFn: *const fn () anyerror!KeyPair,
        deterministicKeyPairFn: *const fn (secret_key: []const u8) anyerror!KeyPair,
        dhFn: *const fn (out: []u8, pk: []const u8, sk: []const u8) anyerror!void,

        /// X25519-HKDF-SHA256
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
                    .public_key = try BoundedArray(u8, max_public_key_length).fromSlice(&kp.public_key),
                    .secret_key = try BoundedArray(u8, max_secret_key_length).fromSlice(&kp.secret_key),
                };
            }

            fn deterministicKeyPair(secret_key: []const u8) !KeyPair {
                debug.assert(secret_key.len == secret_length);
                const public_key = try crypto.dh.X25519.recoverPublicKey(secret_key[0..secret_length].*);
                return KeyPair{
                    .public_key = try BoundedArray(u8, max_public_key_length).fromSlice(&public_key),
                    .secret_key = try BoundedArray(u8, max_secret_key_length).fromSlice(secret_key),
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

        /// Return a suite given a suite ID
        pub fn fromId(id: u16) !Kem {
            return switch (id) {
                X25519HkdfSha256.id => X25519HkdfSha256.kem,
                else => error.UnsupportedKem,
            };
        }
    };

    /// Key derivation functions
    pub const Kdf = struct {
        id: u16,
        prk_length: usize,
        extract: *const fn (out: []u8, salt: []const u8, ikm: []const u8) void,
        expand: *const fn (out: []u8, ctx: []const u8, prk: []const u8) void,

        /// HKDF-SHA-256
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

        /// Return a KDF from a KDF id
        pub fn fromId(id: u16) !Kdf {
            return switch (id) {
                HkdfSha256.id => HkdfSha256.kdf,
                else => error.UnsupportedKdf,
            };
        }
    };

    /// AEADs
    pub const Aead = struct {
        id: u16,
        key_length: usize,
        nonce_length: usize,
        tag_length: usize,
        newStateFn: *const fn (key: []const u8, base_nonce: []const u8) error{ InvalidParameters, Overflow }!State,

        /// An AEAD state
        pub const State = struct {
            base_nonce: BoundedArray(u8, max_aead_nonce_length),
            counter: BoundedArray(u8, max_aead_nonce_length),
            key: BoundedArray(u8, max_aead_key_length),
            encryptFn: *const fn (c: []u8, m: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) void,
            decryptFn: *const fn (m: []u8, c: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) crypto.errors.AuthenticationError!void,

            fn incrementCounter(counter: []u8) void {
                var i = counter.len;
                var carry: u1 = 1;
                while (true) {
                    i -= 1;
                    const res = @addWithOverflow(counter[i], carry);
                    counter[i] = res[0];
                    carry = res[1];
                    if (i == 0) break;
                }
                debug.assert(carry == 0); // Counter overflow
            }

            /// Increment the nonce
            pub fn nextNonce(state: *State) BoundedArray(u8, max_aead_nonce_length) {
                debug.assert(state.counter.len == state.base_nonce.len);
                var base_nonce = @TypeOf(state.base_nonce).fromSlice(state.base_nonce.constSlice()) catch unreachable;
                var nonce = base_nonce.slice();
                var counter = state.counter.slice();
                for (nonce, 0..) |*p, i| {
                    p.* ^= counter[i];
                }
                incrementCounter(counter);
                return BoundedArray(u8, max_aead_nonce_length).fromSlice(nonce) catch unreachable;
            }
        };

        /// AES-128-GCM
        pub const Aes128Gcm = struct {
            const A = crypto.aead.aes_gcm.Aes128Gcm;
            pub const id: u16 = 0x0001;

            fn newState(key: []const u8, base_nonce: []const u8) error{ InvalidParameters, Overflow }!State {
                if (key.len != A.key_length or base_nonce.len != A.nonce_length) {
                    return error.InvalidParameters;
                }
                var counter = try BoundedArray(u8, max_aead_nonce_length).init(A.nonce_length);
                mem.set(u8, counter.slice(), 0);
                var state = State{
                    .base_nonce = try BoundedArray(u8, max_aead_nonce_length).fromSlice(base_nonce),
                    .counter = counter,
                    .key = try BoundedArray(u8, max_aead_key_length).fromSlice(key),
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

        /// Use an external AEAD
        pub const ExportOnly = struct {
            pub const id: u16 = 0xffff;
        };

        /// Return an AEAD given an ID
        pub fn fromId(id: u16) !?Aead {
            return switch (id) {
                Aes128Gcm.id => Aes128Gcm.aead,
                ExportOnly.id => null,
                else => error.UnsupportedKdf,
            };
        }
    };
};

/// A pre-shared key
pub const Psk = struct {
    key: []u8,
    id: []u8,
};

/// A key pair
pub const KeyPair = struct {
    public_key: BoundedArray(u8, max_public_key_length),
    secret_key: BoundedArray(u8, max_secret_key_length),
};

/// An HPKE suite
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

    /// Create an HPKE suite given its components identifiers
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

    /// Extract a PRK out of input keying material and an optional salt
    pub fn extract(suite: Suite, prk: []u8, salt: ?[]const u8, ikm: []const u8) void {
        const prk_length = suite.kdf.prk_length;
        debug.assert(prk.len == prk_length);
        suite.kdf.extract(prk, salt orelse "", ikm);
    }

    /// Expand a PRK into an arbitrary-long key for the context `ctx`
    pub fn expand(suite: Suite, out: []u8, ctx: []const u8, prk: []const u8) void {
        suite.kdf.expand(out, ctx, prk);
    }

    pub const Prk = BoundedArray(u8, max_prk_length);

    /// Create a PRK given a suite ID, a label, input keying material and an optional salt
    pub fn labeledExtract(suite: Suite, suite_id: []const u8, salt: ?[]const u8, label: []const u8, ikm: []const u8) !Prk {
        var buffer: [hpke_version.len + max_suite_id_length + max_label_length + max_ikm_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var secret = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
        try secret.appendSlice(&hpke_version);
        try secret.appendSlice(suite_id);
        try secret.appendSlice(label);
        try secret.appendSlice(ikm);
        var prk = try Prk.init(suite.kdf.prk_length);
        suite.extract(prk.slice(), salt, secret.items);

        return prk;
    }

    /// Expand a PRK using a suite, a label and optional information
    pub fn labeledExpand(suite: Suite, out: []u8, suite_id: []const u8, prk: Prk, label: []const u8, info: ?[]const u8) !void {
        var out_length = [_]u8{ 0, 0 };
        mem.writeIntBig(u16, &out_length, @intCast(u16, out.len));
        var buffer: [out_length.len + hpke_version.len + max_suite_id_length + max_label_length + max_info_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var labeled_info = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
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
        } else if (mode == .psk or mode == .authPsk) {
            return error.PskRequired;
        }
    }

    fn keySchedule(suite: Suite, mode: Mode, dh_secret: []const u8, info: []const u8, psk: ?Psk) !Context {
        try verifyPskInputs(mode, psk);
        const psk_id: []const u8 = if (psk) |p| p.id else &[_]u8{};
        var psk_id_hash = try suite.labeledExtract(&suite.id.context, null, "psk_id_hash", psk_id);
        var info_hash = try suite.labeledExtract(&suite.id.context, null, "info_hash", info);

        var buffer: [1 + max_prk_length + max_prk_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var key_schedule_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
        try key_schedule_ctx.append(@enumToInt(mode));
        try key_schedule_ctx.appendSlice(psk_id_hash.constSlice());
        try key_schedule_ctx.appendSlice(info_hash.constSlice());
        const psk_key: []const u8 = if (psk) |p| p.key else &[_]u8{};
        var secret = try suite.labeledExtract(&suite.id.context, dh_secret, "secret", psk_key);
        var exporter_secret = try BoundedArray(u8, max_prk_length).init(suite.kdf.prk_length);
        try suite.labeledExpand(exporter_secret.slice(), &suite.id.context, secret, "exp", key_schedule_ctx.items);

        var outbound_state = if (suite.aead) |aead| blk: {
            var outbound_key = try BoundedArray(u8, max_aead_key_length).init(aead.key_length);
            try suite.labeledExpand(outbound_key.slice(), &suite.id.context, secret, "key", key_schedule_ctx.items);
            var outbound_base_nonce = try BoundedArray(u8, max_aead_nonce_length).init(aead.nonce_length);
            try suite.labeledExpand(outbound_base_nonce.slice(), &suite.id.context, secret, "base_nonce", key_schedule_ctx.items);
            break :blk try aead.newStateFn(outbound_key.constSlice(), outbound_base_nonce.constSlice());
        } else null;

        return Context{
            .suite = suite,
            .exporter_secret = exporter_secret,
            .outbound_state = outbound_state,
        };
    }

    /// Create a new key pair
    pub fn generateKeyPair(suite: Suite) !KeyPair {
        return suite.kem.generateKeyPairFn();
    }

    /// Create a new deterministic key pair
    pub fn deterministicKeyPair(suite: Suite, seed: []const u8) !KeyPair {
        var prk = try suite.labeledExtract(&suite.id.kem, null, "dkp_prk", seed);
        var secret_key = try BoundedArray(u8, max_secret_key_length).init(suite.kem.secret_length);
        try suite.labeledExpand(secret_key.slice(), &suite.id.kem, prk, "sk", null);
        return suite.kem.deterministicKeyPairFn(secret_key.constSlice());
    }

    fn extractAndExpandDh(suite: Suite, dh: []const u8, kem_ctx: []const u8) !BoundedArray(u8, max_shared_key_length) {
        const prk = try suite.labeledExtract(&suite.id.kem, null, "eae_prk", dh);
        var dh_secret = try BoundedArray(u8, max_digest_length).init(suite.kem.shared_length);
        try suite.labeledExpand(dh_secret.slice(), &suite.id.kem, prk, "shared_secret", kem_ctx);
        return dh_secret;
    }

    /// A secret, and an encapsulated (encrypted) representation of it
    pub const EncapsulatedSecret = struct {
        secret: BoundedArray(u8, max_digest_length),
        encapsulated: BoundedArray(u8, max_public_key_length),
    };

    /// Generate a secret, return it as well as its encapsulation
    pub fn encap(suite: Suite, server_pk: []const u8, seed: ?[]const u8) !EncapsulatedSecret {
        var eph_kp = if (seed) |s| try suite.deterministicKeyPair(s) else try suite.generateKeyPair();
        var dh = try BoundedArray(u8, max_shared_key_length).init(suite.kem.shared_length);
        try suite.kem.dhFn(dh.slice(), server_pk, eph_kp.secret_key.slice());
        var buffer: [max_public_key_length + max_public_key_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var kem_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
        try kem_ctx.appendSlice(eph_kp.public_key.constSlice());
        try kem_ctx.appendSlice(server_pk);
        const dh_secret = try suite.extractAndExpandDh(dh.constSlice(), kem_ctx.items);
        return EncapsulatedSecret{
            .secret = dh_secret,
            .encapsulated = eph_kp.public_key,
        };
    }

    /// Generate a secret, return it as well as its encapsulation, with authentication support
    pub fn authEncap(suite: Suite, server_pk: []const u8, client_kp: KeyPair, seed: ?[]const u8) !EncapsulatedSecret {
        var eph_kp = if (seed) |s| try suite.deterministicKeyPair(s) else try suite.generateKeyPair();
        var dh1 = try BoundedArray(u8, max_shared_key_length).init(suite.kem.shared_length);
        try suite.kem.dhFn(dh1.slice(), server_pk, eph_kp.secret_key.constSlice());
        var dh2 = try BoundedArray(u8, max_shared_key_length).init(suite.kem.shared_length);
        try suite.kem.dhFn(dh2.slice(), server_pk, client_kp.secret_key.constSlice());
        var dh = try BoundedArray(u8, 2 * max_shared_key_length).init(dh1.len + dh2.len);
        mem.copy(u8, dh.slice()[0..dh1.len], dh1.constSlice());
        mem.copy(u8, dh.slice()[dh1.len..][0..dh2.len], dh2.constSlice());
        var buffer: [3 * max_public_key_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var kem_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
        try kem_ctx.appendSlice(eph_kp.public_key.constSlice());
        try kem_ctx.appendSlice(server_pk);
        try kem_ctx.appendSlice(client_kp.public_key.constSlice());
        const dh_secret = try suite.extractAndExpandDh(dh.constSlice(), kem_ctx.items);
        return EncapsulatedSecret{
            .secret = dh_secret,
            .encapsulated = eph_kp.public_key,
        };
    }

    /// Decapsulate a secret
    pub fn decap(suite: Suite, eph_pk: []const u8, server_kp: KeyPair) !BoundedArray(u8, max_shared_key_length) {
        var dh = try BoundedArray(u8, max_shared_key_length).init(suite.kem.shared_length);
        try suite.kem.dhFn(dh.slice(), eph_pk, server_kp.secret_key.constSlice());
        var buffer: [2 * max_public_key_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var kem_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
        try kem_ctx.appendSlice(eph_pk);
        try kem_ctx.appendSlice(server_kp.public_key.constSlice());
        return suite.extractAndExpandDh(dh.constSlice(), kem_ctx.items);
    }

    /// Authenticate a client using its public key and decapsulate a secret
    pub fn authDecap(suite: Suite, eph_pk: []const u8, server_kp: KeyPair, client_pk: []const u8) !BoundedArray(u8, max_shared_key_length) {
        var dh1 = try BoundedArray(u8, max_shared_key_length).init(suite.kem.shared_length);
        try suite.kem.dhFn(dh1.slice(), eph_pk, server_kp.secret_key.constSlice());
        var dh2 = try BoundedArray(u8, max_shared_key_length).init(suite.kem.shared_length);
        try suite.kem.dhFn(dh2.slice(), client_pk, server_kp.secret_key.constSlice());
        var dh = try BoundedArray(u8, 2 * max_shared_key_length).init(dh1.len + dh2.len);
        mem.copy(u8, dh.slice()[0..dh1.len], dh1.constSlice());
        mem.copy(u8, dh.slice()[dh1.len..][0..dh2.len], dh2.constSlice());
        var buffer: [3 * max_public_key_length]u8 = undefined;
        var alloc = FixedBufferAllocator.init(&buffer);
        var kem_ctx = try ArrayList(u8).initCapacity(alloc.allocator(), alloc.buffer.len);
        try kem_ctx.appendSlice(eph_pk);
        try kem_ctx.appendSlice(server_kp.public_key.constSlice());
        try kem_ctx.appendSlice(client_pk);
        return suite.extractAndExpandDh(dh.constSlice(), kem_ctx.items);
    }

    /// A client context as well as an encapsulated secret
    pub const ClientContextAndEncapsulatedSecret = struct {
        client_ctx: ClientContext,
        encapsulated_secret: EncapsulatedSecret,
    };

    /// Create a new client context
    pub fn createClientContext(suite: Suite, server_pk: []const u8, info: []const u8, psk: ?Psk, seed: ?[]const u8) !ClientContextAndEncapsulatedSecret {
        const encapsulated_secret = try suite.encap(server_pk, seed);
        const mode: Mode = if (psk) |_| .psk else .base;
        const inner_ctx = try suite.keySchedule(mode, encapsulated_secret.secret.constSlice(), info, psk);
        const client_ctx = ClientContext{ .ctx = inner_ctx };
        return ClientContextAndEncapsulatedSecret{
            .client_ctx = client_ctx,
            .encapsulated_secret = encapsulated_secret,
        };
    }

    /// Create a new client authenticated context
    pub fn createAuthenticatedClientContext(suite: Suite, client_kp: KeyPair, server_pk: []const u8, info: []const u8, psk: ?Psk, seed: ?[]const u8) !ClientContextAndEncapsulatedSecret {
        const encapsulated_secret = try suite.authEncap(server_pk, client_kp, seed);
        const mode: Mode = if (psk) |_| .authPsk else .auth;
        const inner_ctx = try suite.keySchedule(mode, encapsulated_secret.secret.constSlice(), info, psk);
        const client_ctx = ClientContext{ .ctx = inner_ctx };
        return ClientContextAndEncapsulatedSecret{
            .client_ctx = client_ctx,
            .encapsulated_secret = encapsulated_secret,
        };
    }

    /// Create a new server context
    pub fn createServerContext(suite: Suite, encapsulated_secret: []const u8, server_kp: KeyPair, info: []const u8, psk: ?Psk) !ServerContext {
        const dh_secret = try suite.decap(encapsulated_secret, server_kp);
        const mode: Mode = if (psk) |_| .psk else .base;
        const inner_ctx = try suite.keySchedule(mode, dh_secret.constSlice(), info, psk);
        return ServerContext{ .ctx = inner_ctx };
    }

    /// Create a new authenticated server context
    pub fn createAuthenticatedServerContext(suite: Suite, client_pk: []const u8, encapsulated_secret: []const u8, server_kp: KeyPair, info: []const u8, psk: ?Psk) !ServerContext {
        const dh_secret = try suite.authDecap(encapsulated_secret, server_kp, client_pk);
        const mode: Mode = if (psk) |_| .authPsk else .auth;
        const inner_ctx = try suite.keySchedule(mode, dh_secret.constSlice(), info, psk);
        return ServerContext{ .ctx = inner_ctx };
    }
};

const Context = struct {
    suite: Suite,
    exporter_secret: BoundedArray(u8, max_prk_length),
    inbound_state: ?primitives.Aead.State = null,
    outbound_state: ?primitives.Aead.State = null,

    fn exportSecret(ctx: Context, out: []u8, exporter_context: []const u8) !void {
        try ctx.suite.labeledExpand(out, &ctx.suite.id.context, ctx.exporter_secret, "sec", exporter_context);
    }

    fn responseState(ctx: Context) !primitives.Aead.State {
        var inbound_key = try BoundedArray(u8, max_aead_key_length).init(ctx.suite.aead.?.key_length);
        var inbound_base_nonce = try BoundedArray(u8, max_aead_nonce_length).init(ctx.suite.aead.?.nonce_length);
        try ctx.exportSecret(inbound_key.slice(), "response key");
        try ctx.exportSecret(inbound_base_nonce.slice(), "response nonce");
        return ctx.suite.aead.?.newStateFn(inbound_key.constSlice(), inbound_base_nonce.constSlice());
    }
};

/// A client context
pub const ClientContext = struct {
    ctx: Context,

    /// Encrypt a message for the server
    pub fn encryptToServer(client_context: *ClientContext, ciphertext: []u8, message: []const u8, ad: []const u8) void {
        const required_ciphertext_length = client_context.ctx.suite.aead.?.tag_length + message.len;
        debug.assert(ciphertext.len == required_ciphertext_length);
        var state = &client_context.ctx.outbound_state.?;
        const nonce = state.nextNonce();
        state.encryptFn(ciphertext, message, ad, nonce.constSlice(), state.key.constSlice());
    }

    /// Decrypt a response from the server
    pub fn decryptFromServer(client_context: *ClientContext, message: []u8, ciphertext: []const u8, ad: []const u8) !void {
        if (client_context.ctx.inbound_state == null) {
            client_context.ctx.inbound_state = client_context.ctx.responseState() catch unreachable;
        }
        const required_ciphertext_length = client_context.ctx.suite.aead.?.tag_length + message.len;
        debug.assert(ciphertext.len == required_ciphertext_length);
        var state = &client_context.ctx.inbound_state.?;
        const nonce = state.nextNonce();
        try state.decryptFn(message, ciphertext, ad, nonce.constSlice(), state.key.constSlice());
    }

    /// Return the exporter secret
    pub fn exporterSecret(client_context: ClientContext) BoundedArray(u8, max_prk_length) {
        return client_context.ctx.exporter_secret;
    }

    /// Derive an arbitrary-long secret
    pub fn exportSecret(client_context: ClientContext, out: []u8, info: []const u8) !void {
        try client_context.ctx.exportSecret(out, info);
    }

    /// Return the tag length
    pub fn tagLength(client_context: ClientContext) usize {
        return client_context.ctx.suite.aead.?.tag_length;
    }
};

/// A server context
pub const ServerContext = struct {
    ctx: Context,

    /// Decrypt a ciphertext received from the client
    pub fn decryptFromClient(server_context: *ServerContext, message: []u8, ciphertext: []const u8, ad: []const u8) !void {
        const required_ciphertext_length = server_context.ctx.suite.aead.?.tag_length + message.len;
        debug.assert(ciphertext.len == required_ciphertext_length);
        var state = &server_context.ctx.outbound_state.?;
        const nonce = state.nextNonce();
        try state.decryptFn(message, ciphertext, ad, nonce.constSlice(), state.key.constSlice());
    }

    /// Encrypt a response to the client
    pub fn encryptToClient(server_context: *ServerContext, ciphertext: []u8, message: []const u8, ad: []const u8) void {
        if (server_context.ctx.inbound_state == null) {
            server_context.ctx.inbound_state = server_context.ctx.responseState() catch unreachable;
        }
        const required_ciphertext_length = server_context.ctx.suite.aead.?.tag_length + message.len;
        debug.assert(ciphertext.len == required_ciphertext_length);
        var state = &server_context.ctx.inbound_state.?;
        const nonce = state.nextNonce();
        state.encryptFn(ciphertext, message, ad, nonce.constSlice(), state.key.constSlice());
    }

    /// Return the exporter secret
    pub fn exporterSecret(server_context: ServerContext) BoundedArray(u8, max_prk_length) {
        return server_context.ctx.exporter_secret;
    }

    /// Derive an arbitrary-long secret
    pub fn exportSecret(server_context: ServerContext, out: []u8, info: []const u8) !void {
        try server_context.ctx.exportSecret(out, info);
    }

    /// Return the tag length
    pub fn tagLength(server_context: ServerContext) usize {
        return server_context.ctx.suite.aead.?.tag_length;
    }
};

test {
    _ = @import("tests.zig");
}
