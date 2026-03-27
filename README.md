# HPKE for Zig

A Zig implementation of [Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html) (HPKE, RFC 9180).

Supports X25519, P-256, and P-384 KEMs with HKDF-SHA256/384/512 and AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 AEADs. All four modes are available: base, PSK, auth, and auth+PSK.

## Usage

### Creating an HPKE instance

Pick a cipher suite and create an `Hpke` instance:

```zig
const hpke = @import("hpke");

const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);
```

Other supported suites include `.p256_hkdf_sha256_aes128_gcm`, `.p384_hkdf_sha384_aes256_gcm`, `.x25519_hkdf_sha256_chacha20_poly1305`, and more.

See `CipherSuiteId` for the full list.

### Generating a key pair

Using `deriveKeyPair` (deterministic, from a seed):

```zig
var seed: [32]u8 = undefined;
io.random(&seed);
const kp = h.deriveKeyPair(&seed);
const sk_r = kp.sk[0..32];
const pk_r = kp.pk[0..32];
```

Or directly for X25519:

```zig
var sk_r: [32]u8 = undefined;
io.random(&sk_r);
const pk_r = try std.crypto.dh.X25519.recoverPublicKey(sk_r);
```

### Sender: encrypt a message

The sender creates a context using the recipient's public key. This produces an encapsulated key (`enc`) that must be sent alongside any ciphertexts.

```zig
var sender = try h.senderSetup(&pk_r, "info", io);

const plaintext = "Hello, HPKE!";
var ciphertext: [plaintext.len + 16]u8 = undefined;
try sender.ctx.seal(&ciphertext, plaintext, "associated data");
```

Send `sender.enc[0..sender.enc_length]` and `ciphertext` to the recipient.

Nonces are incremented automatically, so `seal` can be called multiple times on the same context. The ciphertext is 16 bytes (the AEAD tag) longer than the plaintext.

### Recipient: decrypt a message

The recipient reconstructs the context from the encapsulated key and their secret key:

```zig
var recipient = try h.recipientSetup(enc, &sk_r, "info");

var decrypted: [plaintext.len]u8 = undefined;
try recipient.open(&decrypted, &ciphertext, "associated data");
```

Sender and recipient use distinct types (`SenderContext` and `RecipientContext`), so calling `seal` on a recipient or `open` on a sender is a compile error.

### PSK mode

Both sender and recipient can use a pre-shared key for additional authentication:

```zig
var sender = try h.senderSetupPSK(&pk_r, "info", "my-psk", "psk-id", io);
var recipient = try h.recipientSetupPSK(enc, &sk_r, "info", "my-psk", "psk-id");
```

### Auth mode

The sender authenticates with their own secret key:

```zig
var sender = try h.senderSetupAuth(&pk_r, "info", &sk_s, io);
var recipient = try h.recipientSetupAuth(enc, &sk_r, "info", &pk_s);
```

Auth+PSK combines both:

```zig
var sender = try h.senderSetupAuthPSK(&pk_r, "info", "my-psk", "psk-id", &sk_s, io);
var recipient = try h.recipientSetupAuthPSK(enc, &sk_r, "info", "my-psk", "psk-id", &pk_s);
```

### Export secrets

Both sender and recipient contexts can derive export secrets:

```zig
var secret: [32]u8 = undefined;
sender.ctx.exportSecret(&secret, "label");
recipient.exportSecret(&secret, "label");
```

The `export_only` suites (e.g. `.x25519_hkdf_sha256_export_only`) only support `exportSecret` -- `seal` and `open` return `error.ExportOnlyMode`.

### Wire format helpers

Serialize and parse cipher suite IDs for use in protocols like TLS:

```zig
const bytes = hpke.serializeSuiteId(.x25519_hkdf_sha256_aes128_gcm);
const suite_id = hpke.parseSuiteId(bytes);
```

### Building a suite from components

```zig
const suite_id = hpke.CipherSuiteId.fromComponents(
    .x25519_sha256,
    .hkdf_sha256,
    .aes128_gcm,
);
```
