const std = @import("std");
const hpke = @import("hpke");
const testing = std.testing;

fn countAad(buf: []u8, seq: usize) ![]const u8 {
    return std.fmt.bufPrint(buf, "Count-{d}", .{seq});
}

test "basic encrypt/decrypt roundtrip" {
    const io = testing.io;
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);

    var sk_r: [32]u8 = undefined;
    io.random(&sk_r);
    const pk_r = try std.crypto.dh.X25519.recoverPublicKey(sk_r);

    var sender = try h.senderSetup(&pk_r, "test info", io);
    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], &sk_r, "test info");

    const pt = "Hello, HPKE!";
    var ct: [pt.len + 16]u8 = undefined;
    try sender.ctx.seal(&ct, pt, "aad");

    var decrypted: [pt.len]u8 = undefined;
    try recipient.open(&decrypted, &ct, "aad");

    try testing.expectEqualSlices(u8, pt, &decrypted);
}

test "export secret" {
    const io = testing.io;
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);

    var sk_r: [32]u8 = undefined;
    io.random(&sk_r);
    const pk_r = try std.crypto.dh.X25519.recoverPublicKey(sk_r);

    var sender = try h.senderSetup(&pk_r, "test info", io);
    const recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], &sk_r, "test info");

    var sender_export: [32]u8 = undefined;
    var recipient_export: [32]u8 = undefined;
    sender.ctx.exportSecret(&sender_export, "exported secret");
    recipient.exportSecret(&recipient_export, "exported secret");

    try testing.expectEqualSlices(u8, &sender_export, &recipient_export);
}

test "wrong key fails decryption" {
    const io = testing.io;
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);

    var sk_r: [32]u8 = undefined;
    io.random(&sk_r);
    const pk_r = try std.crypto.dh.X25519.recoverPublicKey(sk_r);

    var sender = try h.senderSetup(&pk_r, "test info", io);

    var wrong_sk: [32]u8 = undefined;
    io.random(&wrong_sk);
    var wrong_recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], &wrong_sk, "test info");

    const pt = "secret message";
    var ct: [pt.len + 16]u8 = undefined;
    try sender.ctx.seal(&ct, pt, "aad");

    var decrypted: [pt.len]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, wrong_recipient.open(&decrypted, &ct, "aad"));
}

test "cipher suite component roundtrip" {
    const suites = [_]hpke.CipherSuiteId{
        .x25519_hkdf_sha256_aes128_gcm,
        .p256_hkdf_sha256_aes128_gcm,
        .p384_hkdf_sha384_aes256_gcm,
        .xwing_hkdf_sha256_aes128_gcm,
        .xwing_hkdf_sha256_aes256_gcm,
    };

    for (suites) |suite_id| {
        const components = suite_id.getComponents();
        const reconstructed = hpke.CipherSuiteId.fromComponents(components.kem, components.kdf, components.aead);
        try testing.expectEqual(suite_id, reconstructed.?);
    }
}

test "wire format serialize/parse roundtrip" {
    const suite_id: hpke.CipherSuiteId = .x25519_hkdf_sha256_chacha20_poly1305;
    const serialized = hpke.serializeSuiteId(suite_id);
    const parsed = hpke.parseSuiteId(serialized);
    try testing.expectEqual(suite_id, parsed.?);
}

test "test vectors" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);

    var info: [20]u8 = undefined;
    _ = try hexToBytes(&info, "4f6465206f6e2061204772656369616e2055726e");

    var server_seed: [32]u8 = undefined;
    _ = try hexToBytes(&server_seed, "29e5fcb544130784b7606e3160d736309d63e044c241d4461a9c9d2e9362f1db");
    const server_kp = h.deriveKeyPair(&server_seed);
    const server_sk = server_kp.sk[0..32];
    const server_pk = server_kp.pk[0..32];

    var expected_sk: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk, "ad5e716159a11fdb33527ce98fe39f24ae3449ffb6e93e8911f62c0e9781718a");
    try testing.expectEqualSlices(u8, &expected_sk, server_sk);

    var expected_pk: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk, "46570dfa9f66e17c38e7a081c65cf42bc00e6fed969d326c692748ae866eac6f");
    try testing.expectEqualSlices(u8, &expected_pk, server_pk);

    var client_seed: [32]u8 = undefined;
    _ = try hexToBytes(&client_seed, "3b8ed55f38545e6ea459b6838280b61ff4f5df2a140823373380609fb6c68933");
    const client_kp = h.deriveKeyPair(&client_seed);
    const client_sk_e = client_kp.sk[0..32];

    var sender = try h.senderSetupDeterministic(server_pk, &info, client_sk_e);
    const enc = sender.enc[0..sender.enc_length];

    var expected_enc: [32]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "e7d9aa41faa0481c005d1343b26939c0748a5f6bf1f81fbd1a4e924bf0719149");
    try testing.expectEqualSlices(u8, &expected_enc, enc);

    const message = "message";
    const aad = "ad";

    var c1: [message.len + 16]u8 = undefined;
    try sender.ctx.seal(&c1, message, aad);
    var expected_c1: [message.len + 16]u8 = undefined;
    _ = try hexToBytes(&expected_c1, "dc54a1124854e041089e52066349a238380aaf6bf98a4c");
    try testing.expectEqualSlices(u8, &expected_c1, &c1);

    var c2: [message.len + 16]u8 = undefined;
    try sender.ctx.seal(&c2, message, aad);
    var expected_c2: [message.len + 16]u8 = undefined;
    _ = try hexToBytes(&expected_c2, "37fbdf5f21e77f15291212fe94579054f56eaf5e78f2b5");
    try testing.expectEqualSlices(u8, &expected_c2, &c2);

    var expected_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_nonce, "ede5198c19b2591389fc7cea");
    try testing.expectEqualSlices(u8, &expected_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exp: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exp, "d27ca8c6ce9d8998f3692613c29e5ae0b064234b874a52d65a014eeffed429b9");
    try testing.expectEqualSlices(u8, &expected_exp, sender.ctx.exporter_secret[0..32]);

    var recipient = try h.recipientSetup(enc, server_sk, &info);
    var d1: [message.len]u8 = undefined;
    try recipient.open(&d1, &c1, aad);
    try testing.expectEqualSlices(u8, message, &d1);

    var d2: [message.len]u8 = undefined;
    try recipient.open(&d2, &c2, aad);
    try testing.expectEqualSlices(u8, message, &d2);
}

test "RFC 9180 A.1: X25519/HKDF-SHA256/AES-128-GCM base mode" {
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);
    const hexToBytes = std.fmt.hexToBytes;

    var ikm_e: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_e, "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    const kp_e = h.deriveKeyPair(&ikm_e);

    var expected_sk_e: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_e, "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    try testing.expectEqualSlices(u8, &expected_sk_e, kp_e.sk[0..32]);

    var expected_pk_e: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk_e, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    try testing.expectEqualSlices(u8, &expected_pk_e, kp_e.pk[0..32]);

    var ikm_r: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_r, "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    const kp_r = h.deriveKeyPair(&ikm_r);

    var expected_sk_r: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_r, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    try testing.expectEqualSlices(u8, &expected_sk_r, kp_r.sk[0..32]);

    var expected_pk_r: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk_r, "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    try testing.expectEqualSlices(u8, &expected_pk_r, kp_r.pk[0..32]);

    var info: [20]u8 = undefined;
    _ = try hexToBytes(&info, "4f6465206f6e2061204772656369616e2055726e");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..32], &info, kp_e.sk[0..32]);

    var expected_enc: [32]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..32]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "4531685d41d65f03dc48f6b8302c05b0");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);

    var expected_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_nonce, "56d890e5accaaf011cff4b7d");
    try testing.expectEqualSlices(u8, &expected_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exp: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exp, "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");
    try testing.expectEqualSlices(u8, &expected_exp, sender.ctx.exporter_secret[0..32]);

    var pt: [29]u8 = undefined;
    _ = try hexToBytes(&pt, "4265617574792069732074727574682c20747275746820626561757479");
    var aad_buf: [16]u8 = undefined;
    const aad = try countAad(&aad_buf, 0);

    var ct: [29 + 16]u8 = undefined;
    try sender.ctx.seal(&ct, &pt, aad);

    var expected_ct: [29 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");
    try testing.expectEqualSlices(u8, &expected_ct, &ct);

    var recipient = try h.recipientSetup(sender.enc[0..32], kp_r.sk[0..32], &info);
    var decrypted: [29]u8 = undefined;
    try recipient.open(&decrypted, &ct, aad);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    var export_val: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_val, "");
    var expected_export: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export, "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee");
    try testing.expectEqualSlices(u8, &expected_export, &export_val);

    var export_zero: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_zero, &[_]u8{0});
    var expected_export_zero: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export_zero, "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5");
    try testing.expectEqualSlices(u8, &expected_export_zero, &export_zero);

    var export_text: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_text, "TestContext");
    var expected_export_text: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export_text, "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931");
    try testing.expectEqualSlices(u8, &expected_export_text, &export_text);

    for (1..257) |seq| {
        const aad_seq = try countAad(&aad_buf, seq);
        var ct_seq: [29 + 16]u8 = undefined;
        try sender.ctx.seal(&ct_seq, &pt, aad_seq);

        switch (seq) {
            1 => {
                var expected: [29 + 16]u8 = undefined;
                _ = try hexToBytes(&expected, "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84");
                try testing.expectEqualSlices(u8, &expected, &ct_seq);
            },
            2 => {
                var expected: [29 + 16]u8 = undefined;
                _ = try hexToBytes(&expected, "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180");
                try testing.expectEqualSlices(u8, &expected, &ct_seq);
            },
            4 => {
                var expected: [29 + 16]u8 = undefined;
                _ = try hexToBytes(&expected, "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d");
                try testing.expectEqualSlices(u8, &expected, &ct_seq);
            },
            255 => {
                var expected: [29 + 16]u8 = undefined;
                _ = try hexToBytes(&expected, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a");
                try testing.expectEqualSlices(u8, &expected, &ct_seq);
            },
            256 => {
                var expected: [29 + 16]u8 = undefined;
                _ = try hexToBytes(&expected, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2");
                try testing.expectEqualSlices(u8, &expected, &ct_seq);
            },
            else => {},
        }

        var decrypted_seq: [29]u8 = undefined;
        try recipient.open(&decrypted_seq, &ct_seq, aad_seq);
        try testing.expectEqualSlices(u8, &pt, &decrypted_seq);
    }
}

test "RFC 9180 A.3: X25519/HKDF-SHA256/AES-128-GCM PSK mode" {
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);
    const hexToBytes = std.fmt.hexToBytes;

    var ikm_e: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_e, "78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b");
    const kp_e = h.deriveKeyPair(&ikm_e);

    var ikm_r: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_r, "d4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098");
    const kp_r = h.deriveKeyPair(&ikm_r);

    var expected_sk_r: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_r, "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd");
    try testing.expectEqualSlices(u8, &expected_sk_r, kp_r.sk[0..32]);

    var info: [20]u8 = undefined;
    _ = try hexToBytes(&info, "4f6465206f6e2061204772656369616e2055726e");

    var psk: [32]u8 = undefined;
    _ = try hexToBytes(&psk, "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");

    var psk_id: [22]u8 = undefined;
    _ = try hexToBytes(&psk_id, "456e6e796e20447572696e206172616e204d6f726961");

    var sender = try h.senderSetupDeterministicPSK(kp_r.pk[0..32], &info, &psk, &psk_id, kp_e.sk[0..32]);

    var expected_enc: [32]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..32]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "15026dba546e3ae05836fc7de5a7bb26");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);

    var expected_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_nonce, "9518635eba129d5ce0914555");
    try testing.expectEqualSlices(u8, &expected_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exp: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exp, "3d76025dbbedc49448ec3f9080a1abab6b06e91c0b11ad23c912f043a0ee7655");
    try testing.expectEqualSlices(u8, &expected_exp, sender.ctx.exporter_secret[0..32]);

    var pt: [29]u8 = undefined;
    _ = try hexToBytes(&pt, "4265617574792069732074727574682c20747275746820626561757479");
    var aad: [7]u8 = undefined;
    _ = try hexToBytes(&aad, "436f756e742d30");

    var ct: [29 + 16]u8 = undefined;
    try sender.ctx.seal(&ct, &pt, &aad);

    var expected_ct: [29 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct, "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea");
    try testing.expectEqualSlices(u8, &expected_ct, &ct);

    var recipient = try h.recipientSetupPSK(sender.enc[0..32], kp_r.sk[0..32], &info, &psk, &psk_id);
    var decrypted: [29]u8 = undefined;
    try recipient.open(&decrypted, &ct, &aad);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    var export_val: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_val, "");
    var expected_export: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export, "dff17af354c8b41673567db6259fd6029967b4e1aad13023c2ae5df8f4f43bf6");
    try testing.expectEqualSlices(u8, &expected_export, &export_val);
}

test "RFC 9180 A.1.3: X25519/HKDF-SHA256/AES-128-GCM auth mode" {
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);
    const hexToBytes = std.fmt.hexToBytes;

    var ikm_e: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_e, "6e6d8f200ea2fb20c30b003a8b4f433d2f4ed4c2658d5bc8ce2fef718059c9f7");
    const kp_e = h.deriveKeyPair(&ikm_e);

    var expected_sk_e: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_e, "ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518");
    try testing.expectEqualSlices(u8, &expected_sk_e, kp_e.sk[0..32]);

    var expected_pk_e: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk_e, "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76");
    try testing.expectEqualSlices(u8, &expected_pk_e, kp_e.pk[0..32]);

    var ikm_r: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_r, "f1d4a30a4cef8d6d4e3b016e6fd3799ea057db4f345472ed302a67ce1c20cdec");
    const kp_r = h.deriveKeyPair(&ikm_r);

    var expected_sk_r: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_r, "fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e");
    try testing.expectEqualSlices(u8, &expected_sk_r, kp_r.sk[0..32]);

    var expected_pk_r: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk_r, "1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e");
    try testing.expectEqualSlices(u8, &expected_pk_r, kp_r.pk[0..32]);

    var ikm_s: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_s, "94b020ce91d73fca4649006c7e7329a67b40c55e9e93cc907d282bbbff386f58");
    const kp_s = h.deriveKeyPair(&ikm_s);

    var expected_sk_s: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_s, "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd");
    try testing.expectEqualSlices(u8, &expected_sk_s, kp_s.sk[0..32]);

    var expected_pk_s: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk_s, "8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b");
    try testing.expectEqualSlices(u8, &expected_pk_s, kp_s.pk[0..32]);

    var info: [20]u8 = undefined;
    _ = try hexToBytes(&info, "4f6465206f6e2061204772656369616e2055726e");

    var sender = try h.senderSetupDeterministicAuth(kp_r.pk[0..32], &info, kp_s.sk[0..32], kp_e.sk[0..32]);
    var recipient = try h.recipientSetupAuth(sender.enc[0..32], kp_r.sk[0..32], &info, kp_s.pk[0..32]);

    var expected_enc: [32]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..32]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "b062cb2c4dd4bca0ad7c7a12bbc341e6");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);

    var expected_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_nonce, "a1bc314c1942ade7051ffed0");
    try testing.expectEqualSlices(u8, &expected_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exp: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exp, "ee1a093e6e1c393c162ea98fdf20560c75909653550540a2700511b65c88c6f1");
    try testing.expectEqualSlices(u8, &expected_exp, sender.ctx.exporter_secret[0..32]);

    var pt: [29]u8 = undefined;
    _ = try hexToBytes(&pt, "4265617574792069732074727574682c20747275746820626561757479");
    var aad_buf: [16]u8 = undefined;
    const aad = try countAad(&aad_buf, 0);

    var ct: [29 + 16]u8 = undefined;
    try sender.ctx.seal(&ct, &pt, aad);

    var expected_ct: [29 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct, "5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e21b680c141b");
    try testing.expectEqualSlices(u8, &expected_ct, &ct);

    var decrypted: [29]u8 = undefined;
    try recipient.open(&decrypted, &ct, aad);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    var export_empty: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_empty, "");
    var expected_export_empty: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export_empty, "28c70088017d70c896a8420f04702c5a321d9cbf0279fba899b59e51bac72c85");
    try testing.expectEqualSlices(u8, &expected_export_empty, &export_empty);

    var export_zero: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_zero, &[_]u8{0});
    var expected_export_zero: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export_zero, "25dfc004b0892be1888c3914977aa9c9bbaf2c7471708a49e1195af48a6f29ce");
    try testing.expectEqualSlices(u8, &expected_export_zero, &export_zero);

    var export_text: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_text, "TestContext");
    var expected_export_text: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export_text, "5a0131813abc9a522cad678eb6bafaabc43389934adb8097d23c5ff68059eb64");
    try testing.expectEqualSlices(u8, &expected_export_text, &export_text);
}

test "RFC 9180 A.1.4: X25519/HKDF-SHA256/AES-128-GCM auth+psk mode" {
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);
    const hexToBytes = std.fmt.hexToBytes;

    var ikm_e: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_e, "4303619085a20ebcf18edd22782952b8a7161e1dbae6e46e143a52a96127cf84");
    const kp_e = h.deriveKeyPair(&ikm_e);

    var expected_sk_e: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_e, "14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768");
    try testing.expectEqualSlices(u8, &expected_sk_e, kp_e.sk[0..32]);

    var expected_pk_e: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk_e, "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    try testing.expectEqualSlices(u8, &expected_pk_e, kp_e.pk[0..32]);

    var ikm_r: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_r, "4b16221f3b269a88e207270b5e1de28cb01f847841b344b8314d6a622fe5ee90");
    const kp_r = h.deriveKeyPair(&ikm_r);

    var expected_sk_r: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_r, "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423");
    try testing.expectEqualSlices(u8, &expected_sk_r, kp_r.sk[0..32]);

    var expected_pk_r: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk_r, "1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976");
    try testing.expectEqualSlices(u8, &expected_pk_r, kp_r.pk[0..32]);

    var ikm_s: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_s, "62f77dcf5df0dd7eac54eac9f654f426d4161ec850cc65c54f8b65d2e0b4e345");
    const kp_s = h.deriveKeyPair(&ikm_s);

    var expected_sk_s: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_s, "fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4");
    try testing.expectEqualSlices(u8, &expected_sk_s, kp_s.sk[0..32]);

    var expected_pk_s: [32]u8 = undefined;
    _ = try hexToBytes(&expected_pk_s, "2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e");
    try testing.expectEqualSlices(u8, &expected_pk_s, kp_s.pk[0..32]);

    var info: [20]u8 = undefined;
    _ = try hexToBytes(&info, "4f6465206f6e2061204772656369616e2055726e");

    var psk: [32]u8 = undefined;
    _ = try hexToBytes(&psk, "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");

    var psk_id: [22]u8 = undefined;
    _ = try hexToBytes(&psk_id, "456e6e796e20447572696e206172616e204d6f726961");

    var sender = try h.senderSetupDeterministicAuthPSK(kp_r.pk[0..32], &info, &psk, &psk_id, kp_s.sk[0..32], kp_e.sk[0..32]);
    var recipient = try h.recipientSetupAuthPSK(sender.enc[0..32], kp_r.sk[0..32], &info, &psk, &psk_id, kp_s.pk[0..32]);

    var expected_enc: [32]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..32]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "1364ead92c47aa7becfa95203037b19a");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);

    var expected_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_nonce, "99d8b5c54669807e9fc70df1");
    try testing.expectEqualSlices(u8, &expected_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exp: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exp, "f048d55eacbf60f9c6154bd4021774d1075ebf963c6adc71fa846f183ab2dde6");
    try testing.expectEqualSlices(u8, &expected_exp, sender.ctx.exporter_secret[0..32]);

    var pt: [29]u8 = undefined;
    _ = try hexToBytes(&pt, "4265617574792069732074727574682c20747275746820626561757479");
    var aad_buf: [16]u8 = undefined;
    const aad = try countAad(&aad_buf, 0);

    var ct: [29 + 16]u8 = undefined;
    try sender.ctx.seal(&ct, &pt, aad);

    var expected_ct: [29 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct, "a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40f27e45e141a24001697737533e");
    try testing.expectEqualSlices(u8, &expected_ct, &ct);

    var decrypted: [29]u8 = undefined;
    try recipient.open(&decrypted, &ct, aad);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    var export_empty: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_empty, "");
    var expected_export_empty: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export_empty, "08f7e20644bb9b8af54ad66d2067457c5f9fcb2a23d9f6cb4445c0797b330067");
    try testing.expectEqualSlices(u8, &expected_export_empty, &export_empty);

    var export_zero: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_zero, &[_]u8{0});
    var expected_export_zero: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export_zero, "52e51ff7d436557ced5265ff8b94ce69cf7583f49cdb374e6aad801fc063b010");
    try testing.expectEqualSlices(u8, &expected_export_zero, &export_zero);

    var export_text: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_text, "TestContext");
    var expected_export_text: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export_text, "a30c20370c026bbea4dca51cb63761695132d342bae33a6a11527d3e7679436d");
    try testing.expectEqualSlices(u8, &expected_export_text, &export_text);
}

test "RFC 9180 A.6: P-256/HKDF-SHA256/AES-128-GCM base mode" {
    const h = hpke.Hpke.init(.p256_hkdf_sha256_aes128_gcm);
    const hexToBytes = std.fmt.hexToBytes;

    var ikm_e: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_e, "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e");
    const kp_e = h.deriveKeyPair(&ikm_e);

    var expected_sk_e: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_e, "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb");
    try testing.expectEqualSlices(u8, &expected_sk_e, kp_e.sk[0..32]);

    var expected_pk_e: [65]u8 = undefined;
    _ = try hexToBytes(&expected_pk_e, "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    try testing.expectEqualSlices(u8, &expected_pk_e, kp_e.pk[0..65]);

    var ikm_r: [32]u8 = undefined;
    _ = try hexToBytes(&ikm_r, "668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550");
    const kp_r = h.deriveKeyPair(&ikm_r);

    var expected_sk_r: [32]u8 = undefined;
    _ = try hexToBytes(&expected_sk_r, "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    try testing.expectEqualSlices(u8, &expected_sk_r, kp_r.sk[0..32]);

    var expected_pk_r: [65]u8 = undefined;
    _ = try hexToBytes(&expected_pk_r, "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
    try testing.expectEqualSlices(u8, &expected_pk_r, kp_r.pk[0..65]);

    var info: [20]u8 = undefined;
    _ = try hexToBytes(&info, "4f6465206f6e2061204772656369616e2055726e");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..65], &info, kp_e.sk[0..32]);

    var expected_enc: [65]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..65]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "868c066ef58aae6dc589b6cfdd18f97e");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);

    var expected_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_nonce, "4e0bc5018beba4bf004cca59");
    try testing.expectEqualSlices(u8, &expected_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exp: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exp, "14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f");
    try testing.expectEqualSlices(u8, &expected_exp, sender.ctx.exporter_secret[0..32]);

    var pt: [29]u8 = undefined;
    _ = try hexToBytes(&pt, "4265617574792069732074727574682c20747275746820626561757479");
    var aad: [7]u8 = undefined;
    _ = try hexToBytes(&aad, "436f756e742d30");

    var ct: [29 + 16]u8 = undefined;
    try sender.ctx.seal(&ct, &pt, &aad);

    var expected_ct: [29 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct, "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434");
    try testing.expectEqualSlices(u8, &expected_ct, &ct);

    var recipient = try h.recipientSetup(sender.enc[0..65], kp_r.sk[0..32], &info);
    var decrypted: [29]u8 = undefined;
    try recipient.open(&decrypted, &ct, &aad);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    var export_val: [32]u8 = undefined;
    sender.ctx.exportSecret(&export_val, "");
    var expected_export: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export, "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d");
    try testing.expectEqualSlices(u8, &expected_export, &export_val);
}

test "sender and recipient contexts enforce role separation" {
    comptime {
        std.debug.assert(!@hasDecl(hpke.SenderContext, "open"));
        std.debug.assert(!@hasDecl(hpke.RecipientContext, "seal"));
    }
}

test "setup and export accept long RFC-valid inputs" {
    const io = testing.io;
    const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);

    var ikm_r: [32]u8 = undefined;
    io.random(&ikm_r);
    const kp_r = h.deriveKeyPair(&ikm_r);

    var info: [300]u8 = undefined;
    @memset(&info, 'i');

    var exporter_context: [400]u8 = undefined;
    @memset(&exporter_context, 'x');

    var sender = try h.senderSetup(kp_r.pk[0..32], &info, io);
    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..32], &info);

    const pt = "long-input roundtrip";
    var ct: [pt.len + 16]u8 = undefined;
    try sender.ctx.seal(&ct, pt, "");

    var decrypted: [pt.len]u8 = undefined;
    try recipient.open(&decrypted, &ct, "");
    try testing.expectEqualSlices(u8, pt, &decrypted);

    var sender_export: [32]u8 = undefined;
    var recipient_export: [32]u8 = undefined;
    sender.ctx.exportSecret(&sender_export, &exporter_context);
    recipient.exportSecret(&recipient_export, &exporter_context);
    try testing.expectEqualSlices(u8, &sender_export, &recipient_export);
}

comptime {
    _ = hpke;
}
