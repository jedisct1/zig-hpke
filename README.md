# HPKE for Zig

A Zig implementation of [Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html) (HPKE, RFC 9180) with post-quantum KEM support per [draft-ietf-hpke-pq-04](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/).

## Supported algorithms

### KEMs

Classical (DHKEM):

- X25519 (0x0020)
- P-256 (0x0010)
- P-384 (0x0011)

Post-quantum (ML-KEM, FIPS 203):

- ML-KEM-512 (0x0040)
- ML-KEM-768 (0x0041)
- ML-KEM-1024 (0x0042)

Hybrid PQ/traditional:

- MLKEM768-X25519 (0x647a)
- MLKEM768-P256 (0x0050)
- MLKEM1024-P384 (0x0051)

### KDFs

Two-stage (HKDF):

- HKDF-SHA256 (0x0001)
- HKDF-SHA384 (0x0002)
- HKDF-SHA512 (0x0003)

One-stage (XOF, draft-defined):

- SHAKE128 (0x0010)
- SHAKE256 (0x0011)
- TurboSHAKE128 (0x0012)
- TurboSHAKE256 (0x0013)

### AEADs

- AES-128-GCM (0x0001)
- AES-256-GCM (0x0002)
- ChaCha20-Poly1305 (0x0003)
- Export-only (0xFFFF)

### Modes

All four HPKE modes are supported for classical KEMs: base, PSK, auth, and auth+PSK.

Post-quantum KEMs support base and PSK modes only. Auth and auth+PSK are not defined for PQ KEMs per the draft specification.

## Usage

### Creating an HPKE instance

Pick a cipher suite and create an `Hpke` instance:

```zig
const hpke = @import("hpke");

const h = hpke.Hpke.init(.x25519_hkdf_sha256_aes128_gcm);
```

See `CipherSuiteId` for the full list of supported suites.

### Generating a key pair

Using `deriveKeyPair` (deterministic, from a seed):

```zig
var seed: [32]u8 = undefined;
io.random(&seed);
const kp = h.deriveKeyPair(&seed);
const sk_r = kp.secret_key[0..32];
const pk_r = kp.public_key[0..32];
```

Or directly for X25519:

```zig
var sk_r: [32]u8 = undefined;
io.random(&sk_r);
const pk_r = try std.crypto.dh.X25519.recoverPublicKey(sk_r);
```

For PQ KEMs, secret keys are compact seeds (64 bytes for pure ML-KEM, 32 bytes for hybrids). Use `h.suite.secret_key_length` and `h.suite.public_key_length` to look up the exact lengths for a given suite.

### Sender: encrypt a message

The sender creates a context using the recipient's public key. This produces an encapsulated key (`enc`) that must be sent alongside any ciphertexts.

```zig
var sender = try h.senderSetup(&pk_r, "info", io);

const plaintext = "Hello, HPKE!";
var ciphertext: [plaintext.len + 16]u8 = undefined;
try sender.ctx.seal(&ciphertext, plaintext, "associated data");
```

Send `sender.encapsulatedSecret()` and `ciphertext` to the recipient.

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

### Auth mode (classical KEMs only)

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

Auth modes are not supported for PQ KEMs and will return `error.WeakParameters`.

### Post-quantum example

```zig
const h = hpke.Hpke.init(.ml_kem_768_hkdf_sha256_aes128_gcm);

var ikm_r: [64]u8 = undefined;
io.random(&ikm_r);
const kp_r = h.deriveKeyPair(&ikm_r);

var sender = try h.senderSetup(kp_r.public_key[0..1184], "info", io);

const pt = "Post-quantum hello!";
var ct: [pt.len + 16]u8 = undefined;
try sender.ctx.seal(&ct, pt, "aad");

var recipient = try h.recipientSetup(sender.encapsulatedSecret(), kp_r.secret_key[0..64], "info");
var decrypted: [pt.len]u8 = undefined;
try recipient.open(&decrypted, &ct, "aad");
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
