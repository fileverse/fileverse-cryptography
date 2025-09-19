# Fileverse Cryptography

Fileverse is a privacy-first and decentralized workspace, with collaborative apps for note-taking, spreadsheets, file-sharing, and presentation slides. This repo contains a comprehensive, type-safe cryptographic library for the end-to-end encrypted Fileverse applications, including [dsheets.new](https://sheets.fileverse.io) and [ddocs.new](https://docs.fileverse.io). The library provides a set of easy-to-use cryptographic primitives with a focus on security, type safety, and flexibility, which can be used for any JavaScript/TypeScript applications.

## Features

- **ECIES** (Elliptic Curve Integrated Encryption Scheme) for asymmetric encryption
- **RSA** encryption with envelope encryption support for large messages
- **NaCl Secret Box** for fast, secure symmetric encryption using TweetNaCl
- **HKDF** (HMAC-based Key Derivation Function) for secure key derivation
- **Argon2id** password hashing for secure password storage and key derivation
- **Encoding Utilities** for consistent data format handling
- **Type-Safe API** with TypeScript generics for encoding types
- **Cross-platform** compatible with Node.js and modern browsers

## Installation

```bash
npm install @fileverse/crypto
```

## Usage

### ECIES

Elliptic Curve Integrated Encryption Scheme for secure asymmetric encryption.

```typescript
import {
  generateECKeyPair,
  eciesEncrypt,
  eciesDecrypt,
} from "@fileverse/crypto/ecies";

// Generate a key pair
const keyPair = generateECKeyPair();
// { publicKey: "Uint8Array", privateKey: "Uint8Array" }

// Or generate with base64 encoding
const keyPairB64 = generateECKeyPair("base64");
// { publicKey: string, privateKey: string }

// Encrypt a message
const message = new TextEncoder().encode("Secret message");
const encrypted = eciesEncrypt(keyPair.publicKey, message);

// Decrypt a message
const decrypted = eciesDecrypt(keyPair.privateKey, encrypted);
console.log(new TextDecoder().decode(decrypted)); // "Secret message"

// You can also use the raw format for the encrypted data
const encryptedRaw = eciesEncrypt(keyPair.publicKey, message, "raw");
// { ephemeralPublicKey: string, nonce: string, ciphertext: string, mac: string }
```

#### Shared Secret Derivation

```typescript
import { generateECKeyPair, deriveSharedSecret } from "@fileverse/crypto/ecies";

const aliceKeyPair = generateECKeyPair();
const bobKeyPair = generateECKeyPair();

// Alice derives shared secret using her private key and Bob's public key
const aliceSharedSecret = deriveSharedSecret(
  aliceKeyPair.privateKey,
  bobKeyPair.publicKey
);

// Bob derives the same shared secret using his private key and Alice's public key
const bobSharedSecret = deriveSharedSecret(
  bobKeyPair.privateKey,
  aliceKeyPair.publicKey
);

// aliceSharedSecret === bobSharedSecret
```

### NaCl Secret Box

Fast, secure symmetric encryption using TweetNaCl's secretbox implementation. Perfect for encrypting data when you have a shared secret key.

```typescript
import {
  generateSecretBoxKey,
  secretBoxEncrypt,
  secretBoxDecrypt,
} from "@fileverse/crypto/nacl";

// Generate a secret key (32 bytes)
const secretKey = generateSecretBoxKey();

// Encrypt a message
const message = new TextEncoder().encode("Secret message");
const encrypted = secretBoxEncrypt(secretKey, message);

// Decrypt the message
const decrypted = secretBoxDecrypt(secretKey, encrypted);
console.log(new TextDecoder().decode(decrypted)); // "Secret message"

// URL-safe base64 encoding
const encryptedUrlSafe = secretBoxEncrypt(secretKey, message, true);
```

#### Key Features

- **Authenticated encryption**: Built-in authentication prevents tampering
- **Fast performance**: Optimized for speed using TweetNaCl
- **Secure nonces**: Automatically generates cryptographically secure 24-byte nonces
- **URL-safe encoding**: Optional URL-safe base64 encoding for web applications
- **Type safety**: Full TypeScript support with proper error handling

### RSA

RSA encryption with support for envelope encryption to handle messages of any size.

```typescript
import {
  generateRSAKeyPair,
  rsaEncrypt,
  rsaDecrypt,
  encryptEnvelope,
  decryptEnvelope,
} from "@fileverse/crypto/webcrypto";
import { toBytes } from "@fileverse/crypto/utils";

// Generate an RSA key pair (default 4096 bits)
const keyPair = await generateRSAKeyPair();
// { publicKey: "base64-encoded-string", privateKey: "base64-encoded-string" }

// Or generate with bytes encoding
const keyPairBytes = await generateRSAKeyPair(4096, "bytes");
// { publicKey: Uint8Array, privateKey: Uint8Array }

// Standard RSA encryption (for small messages)
const message = new TextEncoder().encode("Hello, RSA encryption!");
const encrypted = await rsaEncrypt(keyPairBytes.publicKey, message);

// Decrypt
const decrypted = await rsaDecrypt(keyPairBytes.privateKey, toBytes(encrypted));
console.log(new TextDecoder().decode(decrypted)); // "Hello, RSA encryption!"

// For larger messages, use envelope encryption (hybrid RSA/AES)
const largeMessage = new Uint8Array(1024 * 500); // 500KB message
const envelope = await encryptEnvelope(keyPairBytes.publicKey, largeMessage);

// Decrypt envelope
const decryptedLarge = await decryptEnvelope(keyPairBytes.privateKey, envelope);
```

### HKDF

HMAC-based Key Derivation Function for deriving secure cryptographic keys.

```typescript
import { deriveHKDFKey } from "@fileverse/crypto/hkdf";

// Derive a key
const keyMaterial = new TextEncoder().encode("some-secure-key-material");
const salt = new TextEncoder().encode("salt-value");
const info = new TextEncoder().encode("context-info");

// Get key as Uint8Array (default)
const key = deriveHKDFKey(keyMaterial, salt, info);

// Or get key as base64 string
const keyBase64 = deriveHKDFKey(keyMaterial, salt, info, "base64");
```

### Argon2id

Argon2id password hashing for secure password storage and key derivation.

```typescript
import { getArgon2idHash } from "@fileverse/crypto/argon";

// Hash a password with default options
const password = "mySecurePassword123";
const salt = crypto.getRandomValues(new Uint8Array(16)); // 16-byte salt

// Get hash as Uint8Array (default)
const hash = await getArgon2idHash(password, salt);

// Or get hash as base64 string
const hashBase64 = await getArgon2idHash(password, salt, "base64");

// Use custom Argon2 options
const customOptions = {
  t: 3, // time cost (iterations)
  m: 65536, // memory cost in KiB
  p: 4, // parallelism
  dkLen: 32, // derived key length in bytes
};

const customHash = await getArgon2idHash(
  password,
  salt,
  "base64",
  customOptions
);
```

### Encoding Utilities

Utilities for handling encoding conversions consistently.

```typescript
import { toBytes, bytesToBase64, encodeData } from "@fileverse/crypto/utils";

// Convert base64 to Uint8Array
const bytes = toBytes("SGVsbG8gV29ybGQ=");

// Convert Uint8Array to base64
const base64 = bytesToBase64(new TextEncoder().encode("Hello World"));

// Generic encoding with type safety
const data = new TextEncoder().encode("Test data");
const bytesResult = encodeData(data, "bytes"); // Returns Uint8Array
const base64Result = encodeData(data, "base64"); // Returns string
```

## API Reference

### ECIES Module

#### `generateECKeyPair<E extends EncodingType = "bytes">(encoding?: E): EciesKeyPairType<E>`

Generates an ECIES key pair with the specified encoding.

- **Parameters:**
  - `encoding`: Optional. The encoding type to use ("base64" or "bytes"). Default: "bytes".
- **Returns:** An object containing `publicKey` and `privateKey` in the specified encoding.

#### `deriveSharedSecret<E extends EncodingType = "bytes">(privateKey: Uint8Array | string, publicKey: Uint8Array | string, encoding?: E): EncodedReturnType<E>`

Derives a shared secret from a private key and a public key.

- **Parameters:**
  - `privateKey`: The private key (base64 string or Uint8Array).
  - `publicKey`: The public key (base64 string or Uint8Array).
  - `encoding`: Optional. The encoding type for the result. Default: "bytes".
- **Returns:** The shared secret in the specified encoding.

#### `eciesEncrypt(publicKey: string | Uint8Array, data: Uint8Array, format?: "base64" | "raw"): string | EciesCipher`

Encrypts data using ECIES.

- **Parameters:**
  - `publicKey`: The public key (base64 string or Uint8Array).
  - `data`: The data to encrypt.
  - `format`: Optional. The format of the result ("base64" or "raw"). Default: "base64".
- **Returns:** The encrypted data as a string or EciesCipher object.

#### `eciesDecrypt(privateKey: string | Uint8Array, encryptedData: string | EciesCipher): Uint8Array`

Decrypts data using ECIES.

- **Parameters:**
  - `privateKey`: The private key (base64 string or Uint8Array).
  - `encryptedData`: The encrypted data (string or EciesCipher object).
- **Returns:** The decrypted data as a Uint8Array.

### NaCl Secret Box Module

#### `generateSecretBoxKey(): Uint8Array`

Generates a cryptographically secure 32-byte secret key for use with secret box encryption.

- **Returns:** A 32-byte Uint8Array suitable for secret box operations.

#### `secretBoxEncrypt(key: Uint8Array, message: Uint8Array, urlSafe?: boolean): string`

Encrypts data using NaCl's secretbox authenticated encryption.

- **Parameters:**
  - `key`: The 32-byte secret key as a Uint8Array.
  - `message`: The data to encrypt as a Uint8Array.
  - `urlSafe`: Optional. Whether to use URL-safe base64 encoding. Default: false.
- **Returns:** The encrypted data as a base64-encoded string containing nonce and ciphertext.
- **Throws:** Error if the key length is invalid (not 32 bytes).

#### `secretBoxDecrypt(key: Uint8Array, encrypted: string): Uint8Array`

Decrypts data that was encrypted with secretBoxEncrypt.

- **Parameters:**
  - `key`: The 32-byte secret key as a Uint8Array.
  - `encrypted`: The encrypted data string returned by secretBoxEncrypt.
- **Returns:** The decrypted data as a Uint8Array.
- **Throws:**
  - Error if the key length is invalid (not 32 bytes).
  - Error if the encrypted message format is invalid.
  - Error if the nonce length is invalid (not 24 bytes).
  - Error if decryption fails (authentication failure or corrupted data).

### RSA Module

#### `generateRSAKeyPair<E extends EncodingType = "base64">(keySize?: number, encoding?: E): Promise<RsaKeyPairType<E>>`

Generates an RSA key pair with the specified key size and encoding.

- **Parameters:**
  - `keySize`: Optional. The key size in bits. Default: 4096.
  - `encoding`: Optional. The encoding type to use ("base64" or "bytes"). Default: "base64".
- **Returns:** A promise resolving to an object containing `publicKey` and `privateKey` in the specified encoding.

#### `rsaEncrypt<E extends "base64" | "bytes" = "base64">(publicKey: Uint8Array, message: Uint8Array, returnFormat?: E): Promise<E extends "base64" ? string : Uint8Array>`

Encrypts data using RSA-OAEP.

- **Parameters:**
  - `publicKey`: The public key as a Uint8Array.
  - `message`: The data to encrypt.
  - `returnFormat`: Optional. The format of the result ("base64" or "bytes"). Default: "base64".
- **Returns:** A promise resolving to the encrypted data in the specified format.

#### `rsaDecrypt(privateKey: Uint8Array, cipherText: Uint8Array): Promise<Uint8Array>`

Decrypts data using RSA-OAEP.

- **Parameters:**
  - `privateKey`: The private key as a Uint8Array.
  - `cipherText`: The encrypted data.
- **Returns:** A promise resolving to the decrypted data as a Uint8Array.

#### `encryptEnvelope(publicKey: Uint8Array, message: Uint8Array): Promise<string>`

Encrypts a message of any size using envelope encryption (hybrid RSA/AES).

- **Parameters:**
  - `publicKey`: The public key as a Uint8Array.
  - `message`: The data to encrypt.
- **Returns:** A promise resolving to the enveloped ciphertext as a string.

#### `decryptEnvelope(privateKey: Uint8Array, envelopedCipher: string): Promise<Uint8Array>`

Decrypts an envelope-encrypted message.

- **Parameters:**
  - `privateKey`: The private key as a Uint8Array.
  - `envelopedCipher`: The enveloped ciphertext.
- **Returns:** A promise resolving to the decrypted data as a Uint8Array.

### HKDF Module

#### `deriveHKDFKey<E extends EncodingType = "bytes">(keyMaterial: Uint8Array, salt: Uint8Array, info: Uint8Array, encoding?: E): EncodedReturnType<E>`

Derives a key using HKDF.

- **Parameters:**
  - `keyMaterial`: The key material.
  - `salt`: The salt.
  - `info`: The context info.
  - `encoding`: Optional. The encoding type for the result. Default: "bytes".
- **Returns:** The derived key in the specified encoding.

### Argon2id Module

#### `getArgon2idHash<E extends EncodingType = "bytes">(password: string, salt: Uint8Array, returnFormat?: E, opts?: ArgonOpts): Promise<EncodedReturnType<E>>`

Generates an Argon2id hash from a password and salt.

- **Parameters:**
  - `password`: The password to hash.
  - `salt`: The salt as a Uint8Array (recommended: 16 bytes minimum).
  - `returnFormat`: Optional. The encoding type for the result ("base64" or "bytes"). Default: "bytes".
  - `opts`: Optional. Argon2 configuration options. Default uses secure defaults.
- **Returns:** A promise resolving to the hash in the specified encoding.

**Default Argon2 Options:**

- `t`: 2 (time cost/iterations)
- `m`: 102400 (memory cost in KiB, ~100MB)
- `p`: 8 (parallelism)
- `dkLen`: 32 (derived key length in bytes)

### Encoding Utilities

#### `toBytes(base64: string): Uint8Array`

Converts a base64 string to a Uint8Array.

#### `bytesToBase64(bytes: Uint8Array, urlSafe = false): string`

Converts a Uint8Array to a base64 string.

- **Parameters:**
  - `bytes`: The bytes to convert.
  - `urlSafe`: Optional. Whether to use URL-safe base64 encoding. Default: false.
- **Returns:** The base64 encoded string.

#### `encodeData<E extends EncodingType>(data: Uint8Array, encoding: E): EncodedReturnType<E>`

Encodes data in the specified format.

- **Parameters:**
  - `data`: The data to encode.
  - `encoding`: The encoding type ("base64" or "bytes").
- **Returns:** The encoded data in the specified format.

## Technical Implementation

This library leverages the following dependencies for cryptographic operations:

- [@noble/curves](https://github.com/paulmillr/noble-curves) - For elliptic curve cryptography
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) - For cryptographic hash functions
- [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) - For symmetric encryption
- [tweetnacl](https://github.com/dchest/tweetnacl-js) - For NaCl secret box authenticated encryption
- [js-base64](https://github.com/dankogai/js-base64) - For base64 encoding/decoding

## Security Considerations

- This library uses well-established cryptographic primitives but has not undergone a formal security audit.
- Always keep private keys secure and never expose them in client-side code.
- For production use cases with high-security requirements, consider a formal security review.
- The library doesn't handle key storage - use appropriate secure storage mechanisms for your platform.

## Development

### Prerequisites

- Node.js (v14+)
- npm or yarn

### Setup

```bash
# Clone the repository
git clone https://github.com/fileverse/fileverse-cryptography.git
cd crypto

# Install dependencies
npm install

# Run tests
npm test
```

### Building

```bash
# Build the library
npm run build
```

### Running Tests

```bash
# Run all tests
npm test

# Run specific test files
npx vitest run src/ecies/__tests__/core.test.ts
```

## Browser Compatibility

This library supports all modern browsers that implement the Web Crypto API and TextEncoder/TextDecoder APIs:

- Chrome/Edge 60+
- Firefox 55+
- Safari 11+
- iOS Safari 11+

## License

GNU GPL
