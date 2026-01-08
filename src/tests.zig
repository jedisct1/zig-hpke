const std = @import("std");
const hpke = @import("hpke");
const fmt = std.fmt;
const testing = std.testing;
const primitives = hpke.primitives;
const max_aead_tag_length = hpke.max_aead_tag_length;
const Suite = hpke.Suite;

test "hpke" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const suite = try Suite.init(
        primitives.Kem.X25519HkdfSha256.id,
        primitives.Kdf.HkdfSha256.id,
        primitives.Aead.Aes128Gcm.id,
    );

    const info_hex = "4f6465206f6e2061204772656369616e2055726e";
    var info: [info_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&info, info_hex);

    const server_seed_hex = "29e5fcb544130784b7606e3160d736309d63e044c241d4461a9c9d2e9362f1db";
    var server_seed: [server_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&server_seed, server_seed_hex);
    var server_kp = try suite.deterministicKeyPair(&server_seed);

    var expected: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "ad5e716159a11fdb33527ce98fe39f24ae3449ffb6e93e8911f62c0e9781718a");
    try testing.expectEqualSlices(u8, &expected, server_kp.secret_key.slice());
    _ = try fmt.hexToBytes(&expected, "46570dfa9f66e17c38e7a081c65cf42bc00e6fed969d326c692748ae866eac6f");
    try testing.expectEqualSlices(u8, &expected, server_kp.public_key.slice());

    const client_seed_hex = "3b8ed55f38545e6ea459b6838280b61ff4f5df2a140823373380609fb6c68933";
    var client_seed: [client_seed_hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&client_seed, client_seed_hex);
    var client_kp = try suite.deterministicKeyPair(&client_seed);

    var client_ctx_and_encapsulated_secret = try suite.createClientContext(server_kp.public_key.slice(), &info, null, &client_seed, io);
    var encapsulated_secret = client_ctx_and_encapsulated_secret.encapsulated_secret;
    _ = try fmt.hexToBytes(&expected, "e7d9aa41faa0481c005d1343b26939c0748a5f6bf1f81fbd1a4e924bf0719149");
    try testing.expectEqualSlices(u8, &expected, encapsulated_secret.encapsulated.constSlice());

    var client_ctx = client_ctx_and_encapsulated_secret.client_ctx;
    _ = try fmt.hexToBytes(&expected, "d27ca8c6ce9d8998f3692613c29e5ae0b064234b874a52d65a014eeffed429b9");
    try testing.expectEqualSlices(u8, &expected, client_ctx.exporterSecret().constSlice());

    var server_ctx = try suite.createServerContext(encapsulated_secret.encapsulated.constSlice(), server_kp, &info, null);

    const message = "message";
    const ad = "ad";
    var ciphertext: [max_aead_tag_length + message.len]u8 = undefined;
    client_ctx.encryptToServer(&ciphertext, message, ad);
    _ = try fmt.hexToBytes(&expected, "dc54a1124854e041089e52066349a238380aaf6bf98a4c");
    try testing.expectEqualSlices(u8, expected[0..ciphertext.len], &ciphertext);

    var message2: [message.len]u8 = undefined;
    try server_ctx.decryptFromClient(&message2, &ciphertext, ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    client_ctx.encryptToServer(&ciphertext, message, ad);
    _ = try fmt.hexToBytes(&expected, "37fbdf5f21e77f15291212fe94579054f56eaf5e78f2b5");
    try testing.expectEqualSlices(u8, expected[0..ciphertext.len], &ciphertext);

    try server_ctx.decryptFromClient(&message2, &ciphertext, ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    _ = try fmt.hexToBytes(&expected, "ede5198c19b2591389fc7cea");
    const base_nonce = client_ctx.ctx.outbound_state.?.base_nonce.constSlice();
    try testing.expectEqualSlices(u8, base_nonce, expected[0..base_nonce.len]);

    var exported_secret: [expected.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected, "4ab2fe1958f433ebdd2e6302a81a5a7ca91f2ecf2188658524d681be7a9f8e45");
    try client_ctx.exportSecret(&exported_secret, "exported secret");
    try testing.expectEqualSlices(u8, &expected, &exported_secret);
    try server_ctx.exportSecret(&exported_secret, "exported secret");
    try testing.expectEqualSlices(u8, &expected, &exported_secret);

    client_ctx_and_encapsulated_secret = try suite.createAuthenticatedClientContext(
        client_kp,
        server_kp.public_key.constSlice(),
        &info,
        null,
        null,
        io,
    );
    encapsulated_secret = client_ctx_and_encapsulated_secret.encapsulated_secret;
    client_ctx = client_ctx_and_encapsulated_secret.client_ctx;
    server_ctx = try suite.createAuthenticatedServerContext(
        client_kp.public_key.constSlice(),
        encapsulated_secret.encapsulated.constSlice(),
        server_kp,
        &info,
        null,
    );
    client_ctx.encryptToServer(&ciphertext, message, ad);
    try server_ctx.decryptFromClient(&message2, &ciphertext, ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);

    server_ctx.encryptToClient(&ciphertext, message, ad);
    try client_ctx.decryptFromServer(&message2, &ciphertext, ad);
    try testing.expectEqualSlices(u8, message[0..], message2[0..]);
}
