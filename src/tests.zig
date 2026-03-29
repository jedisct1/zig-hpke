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

test "PQ KEM roundtrip: ML-KEM-768" {
    const io = testing.io;
    const h = hpke.Hpke.init(.ml_kem_768_hkdf_sha256_aes128_gcm);

    var ikm_r: [64]u8 = undefined;
    io.random(&ikm_r);
    const kp_r = h.deriveKeyPair(&ikm_r);

    const pk_r = kp_r.pk[0..1184];
    const sk_r = kp_r.sk[0..64];

    var sender = try h.senderSetup(pk_r, "pq test", io);
    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], sk_r, "pq test");

    const pt = "Post-quantum hello!";
    var ct: [pt.len + 16]u8 = undefined;
    try sender.ctx.seal(&ct, pt, "aad");

    var decrypted: [pt.len]u8 = undefined;
    try recipient.open(&decrypted, &ct, "aad");
    try testing.expectEqualSlices(u8, pt, &decrypted);
}

test "PQ KEM roundtrip: MLKEM768-X25519 (X-Wing)" {
    const io = testing.io;
    const h = hpke.Hpke.init(.mlkem768_x25519_hkdf_sha256_chacha20_poly1305);

    var ikm_r: [32]u8 = undefined;
    io.random(&ikm_r);
    const kp_r = h.deriveKeyPair(&ikm_r);

    const pk_r = kp_r.pk[0..1216];
    const sk_r = kp_r.sk[0..32];

    var sender = try h.senderSetup(pk_r, "xwing test", io);
    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], sk_r, "xwing test");

    const pt = "Hybrid PQ hello!";
    var ct: [pt.len + 16]u8 = undefined;
    try sender.ctx.seal(&ct, pt, "aad");

    var decrypted: [pt.len]u8 = undefined;
    try recipient.open(&decrypted, &ct, "aad");
    try testing.expectEqualSlices(u8, pt, &decrypted);
}

test "PQ KEM roundtrip: MLKEM768-P256" {
    const io = testing.io;
    const h = hpke.Hpke.init(.mlkem768_p256_hkdf_sha256_aes128_gcm);

    var ikm_r: [32]u8 = undefined;
    io.random(&ikm_r);
    const kp_r = h.deriveKeyPair(&ikm_r);

    const pk_r = kp_r.pk[0..1249];
    const sk_r = kp_r.sk[0..32];

    var sender = try h.senderSetup(pk_r, "hybrid p256 test", io);
    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], sk_r, "hybrid p256 test");

    const pt = "Hybrid P256 hello!";
    var ct: [pt.len + 16]u8 = undefined;
    try sender.ctx.seal(&ct, pt, "aad");

    var decrypted: [pt.len]u8 = undefined;
    try recipient.open(&decrypted, &ct, "aad");
    try testing.expectEqualSlices(u8, pt, &decrypted);
}

test "PQ KEM rejects auth mode" {
    const io = testing.io;
    const h = hpke.Hpke.init(.ml_kem_768_hkdf_sha256_aes128_gcm);

    var ikm_r: [64]u8 = undefined;
    io.random(&ikm_r);
    const kp_r = h.deriveKeyPair(&ikm_r);

    var ikm_s: [64]u8 = undefined;
    io.random(&ikm_s);
    const kp_s = h.deriveKeyPair(&ikm_s);

    try testing.expectError(
        error.WeakParameters,
        h.senderSetupAuth(kp_r.pk[0..1184], "info", kp_s.sk[0..64], io),
    );
}

test "PQ cipher suite component roundtrip" {
    const suites = [_]hpke.CipherSuiteId{
        .ml_kem_768_hkdf_sha256_aes128_gcm,
        .mlkem768_x25519_hkdf_sha256_chacha20_poly1305,
        .mlkem768_p256_hkdf_sha256_aes128_gcm,
        .mlkem1024_p384_hkdf_sha384_aes256_gcm,
    };

    for (suites) |suite_id| {
        const components = suite_id.getComponents();
        const reconstructed = hpke.CipherSuiteId.fromComponents(components.kem, components.kdf, components.aead);
        try testing.expectEqual(suite_id, reconstructed.?);
    }
}

test "PQ KEM export secret" {
    const io = testing.io;
    const h = hpke.Hpke.init(.ml_kem_768_hkdf_sha256_aes128_gcm);

    var ikm_r: [64]u8 = undefined;
    io.random(&ikm_r);
    const kp_r = h.deriveKeyPair(&ikm_r);

    var sender = try h.senderSetup(kp_r.pk[0..1184], "export test", io);
    const recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..64], "export test");

    var sender_export: [32]u8 = undefined;
    var recipient_export: [32]u8 = undefined;
    sender.ctx.exportSecret(&sender_export, "pq export context");
    recipient.exportSecret(&recipient_export, "pq export context");

    try testing.expectEqualSlices(u8, &sender_export, &recipient_export);
}

test "draft-ietf-hpke-pq-04 vector 0: ML-KEM-512 / HKDF-SHA256 / AES-128-GCM base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.ml_kem_512_hkdf_sha256_aes128_gcm);

    var ikmR: [64]u8 = undefined;
    _ = try hexToBytes(&ikmR, "d7c1c923cee18d6a91cada4526e4d72809749b68ae19fd32fe6c4ec5f82fa9472e336e68c54181766e5a978ecdf20d81977b94253a3827f9d9126bc91532bbe5");

    const kp_r = h.deriveKeyPair(&ikmR);

    var expected_skRm: [64]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "fcc790d47249f00165299da5ea7e8fc878913ad9487ea6f437039dd605cb032e4ed9054818b70b38fa139651fa80187a0f390d71af83d0661c76fb182c9fbd0c");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..64]);

    var expected_pkRm: [800]u8 = undefined;
    _ = try hexToBytes(&expected_pkRm, "b6a325284237f5fb45261cba99882a94d296a8fc6bb1510ee287704b6757cd15638b0901c99b533248210f18325c5cbe34989c62495d3392997023bc0e7c08bf70ac50d973c35533aa890fceb80cac5b4f9b63c0bafa041a451fdc3b61cc82abc252a732646e84561fc9233629143363c486d719c21e5a8e62ab4d5b0c17b00bd0004147bba55f9e865716a157adba8db1e3cc8394354a9157f03c702b9cc5a21a6891aa500af84268605ad3401c2b939c7a0134b9f789aae15ef6d08ce86633c63a0508c262329a2794d05a7a8223a6464302855b9838a586aa57b267b043d06c05600df6991d0da91e84493366e86c664a35ab3b32e75c2a5ea8a0ddb43beeaa1b433257049965daa2c5db268e4d092a20b84d9537af45e58b76d8752ce08c3e379e8769a5f2895d9f7b9bb53b1cb8b357d2c13aa7601c5f6ac858dc51b606732a5b60ea597ea8f342a3a36e8f685e6be6a5d0a62c278b146be384ee273e773539f0c54a51757261210f6993247671b8a9224f12cb2793125dd189a9780a72d35cbe0eb8205a200bdb651f92a9487eeb4a6b4181d2d1160572586bf0bdd6a35652b2074d2883b49610eefc68ab0ba3cf410068dc1724c72516faaafb919c652b3be2f16a59e3642d616d92708028401bae3a287b6bad4f04aace7524e7320586aa1d39942e8c82b03982cc0dc80424f105078a40eb193b8825b451a928e810c9ceaa1d0c4cb0cf061bde80b674fb1ab43636f1c625cc3b22976609b3c854f5973cf23283fce2635194081dd3077ac353aa549b2b670bd0b98957f986d5561b2b9c9dcbec20c19aa83709462c046bff3348c5384238bb035f433a41219ce29c9ab99ba1a89c25cfd47dce7767a56542021a1de8901fca6b7da47615b3599ee1604a40a08f76335d54861c7b415a2620143aa9010aa16f0cc897363729abccb4cc9ca5e6b0429a3012f6039123217a5c7c6e0e99513c3615792258efd51e4518b176fa9b72941328e683a1721fcc518c8983a303a96645f6205dd8200bc4564078949521a6d1e765feeb02a01169be887ef54846dfbc282a92c268ccb23ff031828e0479fd757141b98d0829fccc7ef3c27cda544b3a777affa209d86b5e719d");
    try testing.expectEqualSlices(u8, &expected_pkRm, kp_r.pk[0..800]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");

    var ikmE: [32]u8 = undefined;
    _ = try hexToBytes(&ikmE, "f98936e15de97b6ac920c54f4009166401f882220b8ef2df485f9c077d728ced");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..800], &info, &ikmE);

    var expected_enc: [768]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "3eeb580127af6c5270c93176c82d0ef2e36e168ec1b9b62825d0bbc57c705a1632a7d377c42adea1c15c6a16f489293e8eebadc5341283911feb28d9424a155a4cb7a036a7f7bb92fe63b9d628143cc1c3c9a5864da7047f0dc12472ef4efa79f9616b4d178fd7fef0c37df42d6545f70724e70d8507797a72be14463f8e03501ad954c036fb227bb64d0361d08e1f96e610b2578bf9bfdc9a8b035e79ea1ed0f4891af7200b99bc73e02a30576501ca55dff84c06dcef42cf6f22befe0358cc4205841c4003bb5d02c9c00dd388281c0a1de51d2c172db2b871aa8799de0907ba1e87a7fbceec515650605f0e8a1ef1587e1d8cd0bfe8b435b45eee673f721520b546e05d31a35951d386811d49aa31065fcc2b5f4ca60d4843d88bbc046e708f4870a71bbc48bb734ffda4a810fa2a7da7af8e17ade025f8ab72024f6e04eab7daec46cbe88b2db950d05ce24a20b8f95eb26b880d6ee35a68eb201a67d1c6905d1cbf079835ab673377b2861d3d9b4d3460626d10d9b9b0c98faf0de96300dd570bc0cc59acd577d5c0f5fec89a18e34b5f4f117ace43094f94dab617ff859c2e02cfeb86cfdedaf9c6fced37a977e23312731a2f3032fb82ce5244f1869c0247520734f629fe4799067553849b42922873db8d0d9fae664602aeca96258814a3dc0486cb97e967381a736537aa2604fce066fc0200bfba28ec983399a5ea91acb1054829ca6e1762adb170499e3a361e868f449c3a5aeef935ab594e733f9c4352e6fb565832e3b3e583902ad0d9181c9b6151021a2f04b14cc415bdaa2485f957763452a3f9fe524b6adceae0bb7cdf03d886157a32ef162707dc8a2f71b07eedde31ef112a19cf0d61134bfdf9143c8e2e0ba9ee57641d4a0643c41509dbf7d5a8c96c2c012fcedca100c5ad973a5f1b328a4b7e1f1b3f9126bb572703f9e3da53abdf14c49e32dec3fde3bf4d59cf4e362d09395e3771eca527f9a8944b745ae9b6943cfa404e39343cd361586bae04c712b26e750a26c4fa868cda1252acfbe4d2aaef3738b85f2f8723f299bdbc5b8f65479ffdd328931afbcd522f");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..sender.enc_length]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "53400b5a4cc75259e3bdb222e1081f56");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);

    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "e4f3c7a0c8f2512c6993dee2");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exporter_secret: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "d5a1a92f0f3e88334c14d93e3a999bfab39776e63ed635cb28b59e958e563ada");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..32]);

    // Encryption seq=0
    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);

    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");

    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "9258af357e97f286bf7b5779f0514184651b4e95f6c02febe3d3cf45536738b0b5d6d1c1fa6ec8a2ed1ec3a14e107736510aa6febe6996b5eb192ed5a6a8c1860b7408992fcb30eb14cb");

    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    // Recipient decryption
    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..64], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    // Export seq=0
    var export_ctx0: [13]u8 = undefined;
    _ = try hexToBytes(&export_ctx0, "70736575646f72616e646f6d30");
    var expected_export0: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export0, "7083d75d22e2bf9d1bf257aeb440a6d080573af13907d546d7a85955dba938fd");
    var sender_export0: [32]u8 = undefined;
    sender.ctx.exportSecret(&sender_export0, &export_ctx0);
    try testing.expectEqualSlices(u8, &expected_export0, &sender_export0);
}

test "draft-ietf-hpke-pq-04 vector 1: ML-KEM-768 / HKDF-SHA256 / AES-128-GCM base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.ml_kem_768_hkdf_sha256_aes128_gcm);

    var ikmR: [64]u8 = undefined;
    _ = try hexToBytes(&ikmR, "353e522ee88da0097916c435377e3ffee4cd8288b910a79882f4ac87787cebe6ef7d126a2ef91b2c37f741af42851a08d24a756b225d86d534902829896e726b");
    const kp_r = h.deriveKeyPair(&ikmR);

    var expected_skRm: [64]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "e3408aae322a3628a4d641c2690d4eb212fd66f369782f2dd22fa293476c69957716be20e83920cd26a7710110a34ac3d5da7d90efdc9759812f5cf1a47e85bf");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..64]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");

    var ikmE: [32]u8 = undefined;
    _ = try hexToBytes(&ikmE, "4b3d28ac17e3aadfe767671928e6c0d26c346d4c7dfcf1db0994d131fd76aaba");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..1184], &info, &ikmE);

    var expected_enc: [1088]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "f4c758bd517040c97d327a0d30de9770055583ac2fb90a91a6ec7cca4b464abbd78722db29b985607aea1bb4a79fc76fb784c4d10828e9bfd21495c3e94596c4b626051f30c7028a29c716a2568997392b30179cfbe136fb06b741504dd8901a7291446a692c804859171245d12aa53e0f58b6643a3ba8490180161340f24dfbeb0ab865445ceaa235236ee0db44c119bfe942c7f83d381d7d65172008de0d684de2e87f21394a66bfcf88918832f299469f32fca0e7d5efac51d34b6a788c54922b3b4b7e8325f6306cf545380169773ebdc03fa06ce25aa1c71d307c08bef2016affdd6c293f3cbb0cdb92021692a8ebaef6b74cd6a2bb468da79cc9d08a0494bb88bb2ba0c88d4a3ee2af38762cd6c297c6b36ee18816546b375718876efa557ec600e7c4c6e44aaa3a1372c677dc638dc9742d90319ffc27ee99149c5c8a8185ecf600fdd8be897efea52bfbdc4ef53fff7301ee49a7a352b4890e31c2f44b459b9f7df4623b0be87f1cb9212de1beb19687f3fca6d13ca7f924c0471cf3d9b284e13db8e25e2fd88095ae020100cd9ad5aa5355b8aa90d31657355f80160b3e1e12820908b3a85d321be6d68bebfc7335738b7122de60f4acbb924d3a610749577e8c09574ac0160a3a2f37f9f8af0082082673347db7f2ec20f9d05e96e483411b4c2b18cc49a01ec65ae3a077ba18a7074e5bd14ce97b773687a2cc89b18d9f442d30eebd4925d1591aeba4a04c1a69a7cc6cf34e2581300a27b2bbe9c2fec61ed1b63e50f8704c2737de13f4a9e53e021c5a314d13951293c0a74cc4f098a458885fee8dcf879ee8fe91ebd2a2ca1ffaa9efd84a042b32e195165ae187d66b27e3cde4334bff1eced50910c3ea026ae049df54ab30791f129caa89180c1b6939f8017ef980de3900bbb32e9bc2e1bc53595c438137c62afa349961772d12694fea979f0f4e70c8176b750eb9002483815984b6747d8d4f301eb0b76987d407b2261adecf580160d3185f49aecace7e82701a2eb70d20c43de1be39c1a26e4b5433e213abb748ed5e6fa088c5843c725336c650fbd73f2ee3f8800e9c07948bedec99f75673545425ab826dfe8a0636f422035bb56ef90b5dfab3592232a0b9a84b1bdd78b610a9c3a89ab3dddeaceae9bc5b5d89c930ca20039b65acceb1dba527b58fd6517a21ba90cfb38a2cec950c3f3b490fa4458fe5ccdf79fbd88ae0a84b02cf980aacd4107c29bff7ac8c2fb9e8c131144d968a8b9f4c5bc75420f6cba590682170f2931c99b41895d68ea474f74829fda255f80c7d4ae7b2b0dbd002684f01aa5a2bb17003817d29f27697778404bb9d07fc46eedea487f50490e9beaaa2be101b0d03ae9612e7574022c49166e1e0ce14187df4c75a134f12f60f74d41645584017404b3da7c7e2dec2eca554fb90eb5c958db7e6f5f19cacd27de4651c52358bb7be407261ae4f16559c9617cbcdea92133114b35c376e174165d56082b0e6e2ea347f4e26b904375da1248a863766d95b2c5a2de36b47");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..sender.enc_length]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "00fc412edb7a5adc4a2994869d1016ef");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);

    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "2a2bd95954150f73d200005e");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exporter_secret: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "3d46ed98c5a563ceada359aee128d69c81704edeba9607700cfe2bf13472db88");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..32]);

    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);
    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");
    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "4793c6f4dc5824a0039d8faf2d84d359fd6cf423eaeee578bbb7830068ba34b576a6e3f4ba03c5c2c62f2b869224a1c5acf96083cd13bdc3623a47bde544171a72aa684b12a562196785");
    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..64], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);
}

test "draft-ietf-hpke-pq-04 vector 4: MLKEM768-X25519 / HKDF-SHA256 / ChaCha20Poly1305 base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.mlkem768_x25519_hkdf_sha256_chacha20_poly1305);

    var ikmR: [32]u8 = undefined;
    _ = try hexToBytes(&ikmR, "b86e76a59fabfc87b30cd7b1f7aaa28a834eb64e7a261c197b9a842893fbce56");
    const kp_r = h.deriveKeyPair(&ikmR);

    var expected_skRm: [32]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "3ec47fa82dd5689d27c6190e724c74ec8f608df3331ce331929e37b829676630");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..32]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");

    var ikmE: [64]u8 = undefined;
    _ = try hexToBytes(&ikmE, "2a1c0a3745fe8a48fb62034d300f54dfe1974a5b2e169e580a8789cb1cf5fd190fc00f3fd899594e01a8b15334b9f3fa03d8de44da86e19f5776850fb689e6c8");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..1216], &info, &ikmE);

    var expected_enc: [1120]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "26759c7b22923ea5cc9c78e3e14c8fc62dcb0a66ce44460966978a7fe9685e0c6d22999d99a3f112c307a6d5b2e63591f41e8a3516ba62908376d664557206e696ae870305ff6ba08125266bc0765672beca90fd5c6dae0d3ddad1506065a9d4f297e0c3e70bb441961df26d7a19d79d1ef7e2ac5e53b32a3c7b4e07f2af2ae65830a3e8d1cb2ac1932fc19ec5434303b62c9d010645cf95a475913da5d77a282b88402e4a77ab17b09559dce8a96c67a27bea8f653ceaca3d278b6ed150fe936dda28b1726665c946cab30363ef89eb878ffcc74caa277a5dab1994193a67967125ebd50986dc16997b8f7484d7d0e27c79ff4b68201c1b4102f5a73322fd3da96bf655d90c9b1e6305e01ab1b3449ea3f458b0e98e1f2d1632825c3b30018bb5eefbcc80f767d0b9e7f9f731e1958083879ebcc1b5bb061e89302c444a85eeed169b10d2520fd47b6a111914f3bda2f31d04f250522ba951012a629fa2cd2192583cc9abd75d02b7a11fd18056c414b8f0e0936535bf9b637c7e614a1ae9b9e907fe9d14243f13625ec92a97599eaa491b9da918b586e27d34c7279205dd76cf0ecdbf60b5aea4cfb9dca41069f3e2fc8f371a7cf3b089ea469d8417bda3149159992399ccd5baf776a0f8966d4742cbedaeac131dde853cb1fbb7b869a4c01cea8a487a2e52e757bf4dfcec23995e5f088804d2cf99c82f087454144cc586845d7cf81249e7ad919ea1b06001ad13501da118ee19859595015b4b1872912dd2d4f5dd854f144ae07038bd8bb2b498f8edcb1c70c2102af768d508a1b4237238c0c6e34a9c819b0ebf28f49505d374095b2b58c7a810cf1e806cb3c79af3bc84c8b657787804e374df2b49be6ac510d43024e65fd031540a7cd45c9348ad9f5511b969be6f9c4d849c1428f611225b0d9a3ae341669ba645baa877cdc34c39f5975f4991a77f86eca2c25ebee63a06928c1bbc9513f35547645e835544c1e4a8f33d7f29c1cfbde6425fa05aeff69f373aa8a281c92817cbe5be9305795354efc71a89462e87ce83919d679dcbfded88f7fff9177f4b49e8a959d9aa78b63feb99fa56735df0f4fc253653a9177f767b307bb2a9e7e4d9042f22cc6c4f177db80efaebfef8a3baa6f1423335c830308c2496118263f0bd361d93f8b4e75a7cba94c2af72dd13ee8926524cfe9df14f79165a3498b9fd631cbb874d25b11315f9acb442512561cf7dc6098a08874fcc704cdd5e84e57811a49e78fbd56e5a8e767617321c295095595ea2b0f4aaca30dd38749ab83532be1bdcf4c32a119e035558bb427dbdb806b4e15cea8df3c098728c2b5e40209c5138531db1b660777544e6a014477a7d1b93eb0f245fe9e7053997c10504ef692f21639c86d8926ddce6886d0c39eb7c59357ee54f81871019593713f4a6df37bf7003358694cff59af9872ca02bf762e20499227dba2f552203459dcc69780ef08d9bab4140d96e1c478f06b63b60c9bfb10d90e31d47570ea949ab8e9b99db6ec2f8a2a77dcb25cc36b733dfc09b8299a9d7b19e68c09ad82703f9b47d34d1a3cbafe42c73f57d0e");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..sender.enc_length]);

    var expected_key: [32]u8 = undefined;
    _ = try hexToBytes(&expected_key, "131c2ebb469b909a40915914afd7ff5e638888ac7195dcaaaef8f9a84f0e4030");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..32]);

    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "2b7a68f19e6cdbd43dda3c6d");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exporter_secret: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "c5362ef3c0008d0e573000c5c25a3f62a3bc7061cd41a384c86c27b37d945bbb");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..32]);

    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);
    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");
    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "c5c591f99092d5e38df0a52699af249c66f8275a863423c076de8147a53e65cc584041c963b77a7e59ea93841b1339b5efda8909b71f74bb0073ad62e899de310c1566dea2fd29eba377");
    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..32], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);
}

test "draft-ietf-hpke-pq-04 vector 3: MLKEM768-P256 / HKDF-SHA256 / AES-128-GCM base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.mlkem768_p256_hkdf_sha256_aes128_gcm);

    var ikmR: [32]u8 = undefined;
    _ = try hexToBytes(&ikmR, "5e28a96731c6665f07bb00811cd70f0d3d6c44666ca54cddbb7e5946053b6415");
    const kp_r = h.deriveKeyPair(&ikmR);

    var expected_skRm: [32]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "724eed44c3843d1f260f79b142ce633d602f7989a53ffc9fd4a68690c8e7baa5");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..32]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");

    var ikmE: [128]u8 = undefined;
    _ = try hexToBytes(&ikmE, "0ec0fee6a71457a9dac898a1c161bf1068e68de093f07754155bb8b8b378c17ed09ead96300cc402a6371b58928592dd93565834a19839e7dda048d8e04ff65c7b645f36738c370fbb2d684f59e16ea08aea04444762fdf3a70a114ecf0ba435c9a1e869578142b445398f49093bcca618f0ae5e810163b1503faf3eeaff0bdc");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..1249], &info, &ikmE);

    var expected_enc: [1153]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "6eeebcc0acbd1805273308d61a4212e9254658f19d51d7b58783ec2750d1d521c0e428620915b0c12274182b3e02d449baae5794d437adae8466560f5c7404d0fce35e752e1daee24709523e70cde70bb16831218d696a6e685d1f5948613a714016f831946127268f7986d92c3c9207355ee62e3f692c69cc3c4421d826d666dd7a3fc574f79137bdc3a55673d8f9b761c8227c01e4bb9d076470d4185a8a2f5961716e761fc7cb514feda5a983cf7641e892f582abf7c76ec04ce7fb6cf8e4f69186b7dcb15193483c930f0e27bb814d985141b628eea98ce282c1f0314f272e527869965ec619a529dd5d78f06d0264ac90bc8290968f525569dfa432068f3b425efd9485c2b657cd2c09a362c276ea48e3f4d7aab046e404d3a3ea39fefd1361c426f37bbe816696270146d216bd5f44fff3c6baf6094db1bf9d8f15e636cbc744cfe1f80a26e122e7c37d1ce23b21988bb4075985b073b11bd467a69a3a4fbd71e1c03af57d5fcff78c0378c2d17ecdb7ac01832ea9f3977345ea8808a9146da604f57409f1257f0d752cbc6d9766780a1732f6900857f108aa427f5262874707f651253eafcc992d222783c9e51843be8aa67ceea9e559670568cc3a58b9f491dcc07a5aa4715d10a4e444fedf423eef13e801af63cc8b0bd0596e25f048c0a4639f3ee194fbaf203c7b6c48316f570fb3bd9b3b20e62608398af3bf74486855f304fb5dc4647616fec92834a6cf7e8c48a24916a24337b42c0ebb98aebec5531b93988112bb78f58113cf37208986c1389e51bb8e59bbaddc78033edda3889af70c2f7df2f93ea43a278f55bf37f818d5c38a6d217b6e40b7f44ce6ab8c0cc574643768aba6d590fdfe9682cb056b0bfaccf92121c76940f8220fbf1a216595d0d6a9f4226ac3811c45aa95033dacf2ab6f7c75f8240af60b18e62396a320694f15485c29307a75a6b09ac089b4e0785747a549a77184f31d18f867e1aa3886e0c03af8dc95e1e3bb103af2602fa6adbd375230ac15c7526c7836aef4dd58e617282ab4c27343f0c78af9c45c2dc0d91b64b6ba7c8015d9688ec6e078814011b7b6de74c3d4fdb1bd41432f9b277bdfd62c84b07b5f13d306fa2b2d98f6f1480f63d7e50a3e7e5f88ed1dae7c5ac0a5159c74447cd885217d66839b9842093aee5af90c68d99f7a4a34514116366e408f6ffcde79ab0c9415cf714d31de88552252643d630ca3ffa81e0cbe7ce3c847dfd41692c876ab79956ba2bad4a724cf5aa2d53390fcc8417373dfd06cdcc69eefb5efc8acacee8026d5596dd09043bd406dec819c2faca2a1530fa63ea37b79e68a192a904c83aaf62237661ac1c9b6410f9c0dc46019e085a0d7319691edb9ac9675bc154f6db01ddd6c1a408ea15c36862264fae32f266dc86dca3a4baf3aba15199bd90113a3b104630df9ab23c9c0230ae718ddb83857cea87562a80ed42268c2029908d2fd55de6baa0773d0059cc4c866c8e9a63ee7285f732b24fff5a34b7b38fdb668e265dbfb887b0474d0e8a0dfe351b682f657bcb310c9e7b31315f7fe53706ec9f62185cfa9c0fce11cbecd134b43acfd25e3959d914539a2501b3b9c8e9fec86b92a2b811fa9bc");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..sender.enc_length]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "cb79279f04960511e17368b7c83df0be");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);

    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "47cdcf9aec36fdf3730d94ce");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exporter_secret: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "0443a178389fa1e426df5a129ef7431df2b7aca64d06c4a72a88118fccf7058f");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..32]);

    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);
    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");
    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "766437e462397ec6d4b78c755a6f41cce023100641c04102fe935b1495cba6aa31323a97af05190a024bd0718581d48c71ff69d06523f6127ffb8f0cffde5b0bc0986fba65bfbbd6c7ff");
    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..32], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);
}

test "draft-ietf-hpke-pq-04 vector 2: ML-KEM-1024 / HKDF-SHA384 / AES-256-GCM base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.ml_kem_1024_hkdf_sha384_aes256_gcm);

    var ikmR: [64]u8 = undefined;
    _ = try hexToBytes(&ikmR, "ece1c121b5cc978bdce5eb8d60e9ff101d65b94379898e800c37f79164a25d03264a357df7cd28214b11e171c94dea2338b736e7dbb6f00a0b1b280ae6ad1ba4");
    const kp_r = h.deriveKeyPair(&ikmR);

    var expected_skRm: [64]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "c58f733ea1245a7a54723c30dbf0837acdd7e93c188692523b53b132b993a25af933368a76bbcbf1212e1d34d7128e32c387dc9b04a7ceb0e2b40e1e5769c57d");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..64]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");

    var ikmE: [32]u8 = undefined;
    _ = try hexToBytes(&ikmE, "0152bf3799ed0803b9ac3e62695c51065fe2cd4a18ff655fb3efe7399c404e19");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..1568], &info, &ikmE);

    var expected_key: [32]u8 = undefined;
    _ = try hexToBytes(&expected_key, "57928282570ac8e002ebc79908293d65faabdb3ef58149edb33083cc2f38a55b");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..32]);

    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "107259b6ac73abb151fb98a8");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exporter_secret: [48]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "9d4faf56b5319ad7a66492576d15522e30d948ed11ed3543daf774c0466b698ce699de9671ef34f9e23a741b7efc5074");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..48]);

    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);
    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");
    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "433d24cb45dba60451bfcdd3fcc9033a55cbcf128f6068a09cc617dee516d02bd1b15d8bb9f8acc788b29086566124414183c07dfe160d135213dc21b34e7320a19e54d979b2ba3f2d66");
    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..64], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);
}

test "draft-ietf-hpke-pq-04 vector 5: MLKEM1024-P384 / HKDF-SHA384 / AES-256-GCM base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.mlkem1024_p384_hkdf_sha384_aes256_gcm);

    var ikmR: [32]u8 = undefined;
    _ = try hexToBytes(&ikmR, "0fce198c0c1ccfca5cd1ca8bc495b06696cbb8c733e708ead4531b2b294c38d2");
    const kp_r = h.deriveKeyPair(&ikmR);

    var expected_skRm: [32]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "dbdae0423ba0e5db3d6322601b8dc302d3051d4677142079c7bdf441f4c448dd");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..32]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");

    var ikmE: [80]u8 = undefined;
    _ = try hexToBytes(&ikmE, "bd1207854ec0963347d5218f900783d6ca0ff62c5e2181ca5a932e2d6d8d96cc9b092a9d709468d10f7e8ec8d9eccd7e7a647d351133e2a2f4b438154d1dd70850af7f7841c1dbd0699feb9852d99c08");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..1665], &info, &ikmE);

    var expected_key: [32]u8 = undefined;
    _ = try hexToBytes(&expected_key, "6f5b0a62d262c2cc2026a8f38b3879abea8042823ca193573e7154953d22dd64");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..32]);

    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "b057357da81f0102a835a35d");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);

    var expected_exporter_secret: [48]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "8865b4be7a2544efeeb3cceb2d0e010adde42cda0fd0b7d4c2230dad1f9c095a87b0ec6ff60bd5d76a1266d75ecac133");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..48]);

    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);
    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");
    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "4c2683632b3d5fc13457a54620085e49e300f1bd03408ad7c6821df4ec8168c2eabbf935541fdeb235e97ae537d1280471735063a5b922746c19d14b5a2830f38fd7a8804c057d9bea2b");
    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..32], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);
}

test "PQ wire format serialize/parse roundtrip" {
    const pq_suites = [_]hpke.CipherSuiteId{
        .ml_kem_512_hkdf_sha256_aes128_gcm,
        .ml_kem_768_hkdf_sha256_aes128_gcm,
        .mlkem768_x25519_hkdf_sha256_chacha20_poly1305,
        .mlkem768_p256_hkdf_sha256_aes128_gcm,
        .mlkem1024_p384_hkdf_sha384_aes256_gcm,
    };
    for (pq_suites) |suite_id| {
        const serialized = hpke.serializeSuiteId(suite_id);
        const parsed = hpke.parseSuiteId(serialized);
        try testing.expectEqual(suite_id, parsed.?);
    }
}

test "draft-ietf-hpke-pq-04 vector 6: P-256 / SHAKE128 / AES-128-GCM base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.p256_shake128_aes128_gcm);

    var ikmR: [32]u8 = undefined;
    _ = try hexToBytes(&ikmR, "c6eedf3e84fca93ef3434208f038538f182693825a803f8a3e5469890d893090");
    const kp_r = h.deriveKeyPair(&ikmR);
    var expected_skRm: [32]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "5822d76fd4586619a9cb6c0c8f823e0544d89ef1de0e6cbb21206800708bd1ec");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..32]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");
    var ikmE: [32]u8 = undefined;
    _ = try hexToBytes(&ikmE, "65c72db26bf7f1f50d18a1fda71905653b88d6f361e365b1c35fc2a7bdc40cc0");
    const kp_e = h.deriveKeyPair(&ikmE);

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..65], &info, kp_e.sk[0..32]);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "104d43e2b37b5d843fdf137d36c765e9");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);
    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "b320e8cab81d613258b5686e");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);
    var expected_exporter_secret: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "a30bc8dac89fd0211eebb68d1e765672d41039ef10df93a56ca9d15755c65b2a");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..32]);

    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);
    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");
    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "593668f9ca772ac7332d676a71fc9736c3699cc0f8cf51ec6c2d6eeaa0b3a0daab2774cf703ac11eb2b89e75a12aca75c86b218c9d95fa3f1155c429537cea322c5afd75e8af2be46687");
    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..32], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    var export_ctx: [13]u8 = undefined;
    _ = try hexToBytes(&export_ctx, "70736575646f72616e646f6d30");
    var expected_export: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export, "e445830750c592c6ed3170d16fc1ef1298812285bb8a6cd06646b8d5e854feb7");
    var sender_export: [32]u8 = undefined;
    sender.ctx.exportSecret(&sender_export, &export_ctx);
    try testing.expectEqualSlices(u8, &expected_export, &sender_export);
}

test "draft-ietf-hpke-pq-04 vector 8: X25519 / TurboSHAKE128 / ChaCha20Poly1305 base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.x25519_turboshake128_chacha20_poly1305);

    var ikmR: [32]u8 = undefined;
    _ = try hexToBytes(&ikmR, "97b023835635fbaeca0d748871b9a420865212e74fbef3d942c331e147149560");
    const kp_r = h.deriveKeyPair(&ikmR);
    var expected_skRm: [32]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "85765ddffb3d34268e05ac28213b6fbef25ae7a43fcc8c03cd6e52977fcd5ee3");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..32]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");
    var ikmE: [32]u8 = undefined;
    _ = try hexToBytes(&ikmE, "6a83220f8a55194c8d8621531a1af58a3e67a9d4ad6ffaa1f04ca52f5af6dc1a");
    const kp_e = h.deriveKeyPair(&ikmE);

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..32], &info, kp_e.sk[0..32]);

    var expected_enc: [32]u8 = undefined;
    _ = try hexToBytes(&expected_enc, "2ab42ac5e099dacf517d69fcd7e6df0c5a6a9e79e765f5c0c33e1437f9638e0f");
    try testing.expectEqualSlices(u8, &expected_enc, sender.enc[0..sender.enc_length]);

    var expected_key: [32]u8 = undefined;
    _ = try hexToBytes(&expected_key, "e12d5464fb07e0b41b917fbb8a28d02026c6233660e94046d64e9a9ab1d9f137");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..32]);
    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "01de599541be16789d9431b5");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);
    var expected_exporter_secret: [32]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "737ce6aebdc271c9c348894ab8e6ba401c273a2822349e7b18cb60de5f601df4");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..32]);

    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);
    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");
    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "5829095764d917cf36a75a6fb3801f3659b6b5910891efbf0754cb9f79eec14a18d171c9722a55d0781042fb2e2314071ef1befa5e6986d9eb485a1b68d4a0889543f0e337d4b2f86592");
    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..32], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    var export_ctx: [13]u8 = undefined;
    _ = try hexToBytes(&export_ctx, "70736575646f72616e646f6d30");
    var expected_export: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export, "6a370b998427c699725e43fe9f16a15994c465408d0c8429ba01459862690620");
    var sender_export: [32]u8 = undefined;
    sender.ctx.exportSecret(&sender_export, &export_ctx);
    try testing.expectEqualSlices(u8, &expected_export, &sender_export);
}

test "draft-ietf-hpke-pq-04 vector 12: ML-KEM-1024 / TurboSHAKE256 / AES-128-GCM base mode" {
    const hexToBytes = std.fmt.hexToBytes;
    const h = hpke.Hpke.init(.ml_kem_1024_turboshake256_aes128_gcm);

    var ikmR: [64]u8 = undefined;
    _ = try hexToBytes(&ikmR, "cfcd8c6d1798c45453ff275bd58e27c8222725354068fd85f00227521cfe275bcd7525205c2b7809fc2eb5c201416a100769b4bb4a64490e821494dba747c87f");
    const kp_r = h.deriveKeyPair(&ikmR);
    var expected_skRm: [64]u8 = undefined;
    _ = try hexToBytes(&expected_skRm, "545f8a47869bbe8231bfa14de61aaa71aaafde79ab6281e3f42e0a28a8868f8fbd405f148b0137bbc46603919e5ac1e768d1e6bb9ac4a9abc05edc5b5a5be726");
    try testing.expectEqualSlices(u8, &expected_skRm, kp_r.sk[0..64]);

    var info: [40]u8 = undefined;
    _ = try hexToBytes(&info, "34663634363532303666366532303631323034373732363536333639363136653230353537323665");
    var ikmE: [32]u8 = undefined;
    _ = try hexToBytes(&ikmE, "ab765f59234788d2c785d7fc0cbb82873d73bfa6b8fc95cdefff6959a52bb9c1");

    var sender = try h.senderSetupDeterministic(kp_r.pk[0..1568], &info, &ikmE);

    var expected_key: [16]u8 = undefined;
    _ = try hexToBytes(&expected_key, "572706a57022ab98af4f4ce1b8de4242");
    try testing.expectEqualSlices(u8, &expected_key, sender.ctx.key[0..16]);
    var expected_base_nonce: [12]u8 = undefined;
    _ = try hexToBytes(&expected_base_nonce, "9bc56885fe63e193ff62b41c");
    try testing.expectEqualSlices(u8, &expected_base_nonce, sender.ctx.base_nonce[0..12]);
    var expected_exporter_secret: [64]u8 = undefined;
    _ = try hexToBytes(&expected_exporter_secret, "bf9a89c68d9d7a6116e833ee5e95ef8ad25d586b5f4faf304604f27fe174c3cd6f87ba8d50e4791ea1c2a8f1780a0a01b3075db65b28d1cfe7f0dd87a806044a");
    try testing.expectEqualSlices(u8, &expected_exporter_secret, sender.ctx.exporter_secret[0..64]);

    const pt_hex = "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739";
    var pt: [58]u8 = undefined;
    _ = try hexToBytes(&pt, pt_hex);
    var aad0: [7]u8 = undefined;
    _ = try hexToBytes(&aad0, "436f756e742d30");
    var expected_ct0: [58 + 16]u8 = undefined;
    _ = try hexToBytes(&expected_ct0, "3f491e91c4f0b61d710c51f5a4cbf06ec2aa1171894418b660345b22ccdd7b8be4314e90caadc4554eb3d0ccef61c231f98547d8a16bca8f8f1556d619a85fb089bac81a24b17203421e");
    var ct0: [58 + 16]u8 = undefined;
    try sender.ctx.seal(&ct0, &pt, &aad0);
    try testing.expectEqualSlices(u8, &expected_ct0, &ct0);

    var recipient = try h.recipientSetup(sender.enc[0..sender.enc_length], kp_r.sk[0..64], &info);
    var decrypted: [58]u8 = undefined;
    try recipient.open(&decrypted, &ct0, &aad0);
    try testing.expectEqualSlices(u8, &pt, &decrypted);

    var export_ctx: [13]u8 = undefined;
    _ = try hexToBytes(&export_ctx, "70736575646f72616e646f6d30");
    var expected_export: [32]u8 = undefined;
    _ = try hexToBytes(&expected_export, "3e7d4943487b9b2a6e56040a271a5fe79b73791f49e9bd18df78ba06a3da7dcf");
    var sender_export: [32]u8 = undefined;
    sender.ctx.exportSecret(&sender_export, &export_ctx);
    try testing.expectEqualSlices(u8, &expected_export, &sender_export);
}

test "one-stage KDF wire format serialize/parse roundtrip" {
    const suites = [_]hpke.CipherSuiteId{
        .p256_shake128_aes128_gcm,
        .p384_shake256_aes256_gcm,
        .x25519_turboshake128_chacha20_poly1305,
        .mlkem768_p256_shake128_aes256_gcm,
        .mlkem768_x25519_shake256_chacha20_poly1305,
        .ml_kem_1024_turboshake256_aes128_gcm,
    };
    for (suites) |suite_id| {
        const serialized = hpke.serializeSuiteId(suite_id);
        const parsed = hpke.parseSuiteId(serialized);
        try testing.expectEqual(suite_id, parsed.?);
    }
}

test "DHKEM + one-stage KDF PSK roundtrip" {
    const io = testing.io;
    const h = hpke.Hpke.init(.x25519_turboshake128_chacha20_poly1305);

    var ikm_r: [32]u8 = undefined;
    io.random(&ikm_r);
    const kp_r = h.deriveKeyPair(&ikm_r);

    const psk = "shared-psk-value";
    const psk_id = "psk-id-0";

    var sender = try h.senderSetupPSK(kp_r.pk[0..32], "psk test", psk, psk_id, io);
    var recipient = try h.recipientSetupPSK(sender.enc[0..sender.enc_length], kp_r.sk[0..32], "psk test", psk, psk_id);

    const pt = "PSK mode with TurboSHAKE128";
    var ct: [pt.len + 16]u8 = undefined;
    try sender.ctx.seal(&ct, pt, "aad");

    var decrypted: [pt.len]u8 = undefined;
    try recipient.open(&decrypted, &ct, "aad");
    try testing.expectEqualSlices(u8, pt, &decrypted);
}

comptime {
    _ = hpke;
}
