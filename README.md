# HPKE for Zig

`zig-hpke` is an implementation of the [Hybrid Public Key Encryption](https://cfrg.github.io/draft-irtf-cfrg-hpke/draft-irtf-cfrg-hpke.html) (HPKE) draft.

## Usage

### Fixed slices

This code heavily relies on the `FixedSlice` type: a type to store small, variable-sized slices whose maximum size is known.

Keys are typically represented using that type, whose raw slice can be accessed with the `constSlice()` function (for a constant slice), or `slice()` (for a mutable slice).

### Suite instantiation

```zig
const suite = try Suite.init(
    primitives.Kem.X25519HkdfSha256.id,
    primitives.Kdf.HkdfSha256.id,
    primitives.Aead.Aes128Gcm.id,
);
```

### Key pair creation

```zig
const kp = try suite.generateKeyPair();
```

### Client: creation and encapsulation of the shared secret

A _client_ initiates a connexion by sending an encrypted secret; a _server_ accepts an encrypted secret from a client, and decrypts it, so that both parties can eventually agree on a shared secret.

```zig
var client_ctx_and_encapsulated_secret =
    try suite.createClientContext(server_kp.public_key.slice(), "info", null, null);

var client_ctx = client_ctx_and_encapsulated_secret.client_ctx;

var encapsulated_secret = client_ctx_and_encapsulated_secret.encapsulated_secret;
```

* `encapsulated_secret.encapsulated` needs to be sent to the server. `encapsulated_secret.encapsulated.secret` must remain secret.
* `client_ctx` can be used to encrypt/decrypt messages exchanged with the server.

To improve misuse resistance, this implementation uses distinct types for the client and the server context: `ClientContext` for the client, and `ServerContext` for the server.

### Server: decapsulation of the shared secret

```zig
var server_ctx =
    try suite.createServerContext(encapsulated_secret.encapsulated.constSlice(), server_kp, "info", null);
```

* `server_ctx` can be used to encrypt/decrypt messages exchanged with the client
* The last parameter is an optional pre-shared key.

### Encryption of a message from the client to the server

A message can be encrypted by the client for the server:

```zig
client_ctx.encryptToServer(&ciphertext, message, ad);
```

Nonces are automatically incremented, so it is safe to call this function multiple times within the same context.

Last parameter is optional associated data.

The ciphertext is `client_ctx.tagLength()` bytes larger than the message.

### Decryption of a ciphertext received by the server

The server can decrypt a ciphertext sent by the client:

```zig
var message2: [message.len]u8 = undefined;
try server_ctx.decryptFromClient(&message2, &ciphertext, ad);
```

Last parameter is optional associated data. The message length is `server_ctx.tagLength()` bytes shorter than the ciphertext.

### Encryption of a message from the server to the client

A message can also be encrypted by the server for the client:

```zig
server_ctx.encryptToClient(&ciphertext, message, ad);
```

Nonces are automatically incremented, so it is safe to call this function multiple times within the same context.

Last parameter is optional associated data.

### Decryption of a ciphertext received by the client

The client can decrypt an encrypted response from the server:

```zig
try client_ctx.decryptFromServer(&message2, &ciphertext, ad);
```

Last parameter is optional associated data.

## Authenticated modes

Authenticated modes, with or without a PSK are supported.

See `createAuthenticatedClientContext` and `createAuthenticatedServerContext`.

### Exporter secret

The exporter secret can be obtained with the `exportedSecret()` function available both in the `ServerContext` and `ClientContext` structures:

```zig
const exporter = client_ctx.exporterSecret().constSlice();
```

### Key derivation

```zig
const secret1 = try client_ctx.exportSecret("description 1")
const secret2 = try server_ctx.exportSecret("description 2");
```

### Access the raw cipher interface

```zig
const aead = suite.aead;
```

## That's it!