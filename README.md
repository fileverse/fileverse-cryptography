# Fileverse Cryptography

Fileverse is a privacy-first and decentralized workspace, with collaborative apps for note-taking, spreadsheets, file-sharing, and presentation slides. This repo contains a comprehensive, type-safe cryptographic library for the end-to-end encrypted Fileverse applications, including [dsheets.new](https://sheets.fileverse.io) and [ddocs.new](https://docs.fileverse.io). The library provides a set of easy-to-use cryptographic primitives with a focus on security, type safety, and flexibility, which can be used for any JavaScript/TypeScript applications.

## Features

- **ECIES** (Elliptic Curve Integrated Encryption Scheme) for asymmetric encryption
- **RSA** encryption with envelope encryption support for large messages
- **Post-Quantum Encryption** with HPKE (RFC 9180) over the X-Wing hybrid KEM (ML-KEM-768 + X25519)
- **Identity PQ Primitives** for post-quantum identity public keys and deterministic PQ seed derivation
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

### Post-Quantum Encryption (X-Wing)

Hybrid post-quantum public-key encryption: HPKE (RFC 9180) with the X-Wing KEM (ML-KEM-768 + X25519), HKDF-SHA256 and AES-256-GCM. A ciphertext stays confidential as long as either ML-KEM-768 or X25519 holds.

```typescript
import {
  generatePqKeyPair,
  getPublicKey,
  pqEncrypt,
  pqDecrypt,
} from "@fileverse/crypto/pq";

// Generate a key pair (the private key is a 32-byte seed)
const keyPair = await generatePqKeyPair();
// { publicKey: Uint8Array (1216 bytes), privateKey: Uint8Array (32 bytes) }

// Or derive one deterministically from a 32-byte seed, base64 encoded
const seed = crypto.getRandomValues(new Uint8Array(32));
const seededKeyPair = await generatePqKeyPair(seed, "base64");

// Recompute the public key from a private key
const publicKey = await getPublicKey(keyPair.privateKey);

// Encrypt a message
const message = new TextEncoder().encode("Secret message");
const encrypted = await pqEncrypt(keyPair.publicKey, message);
// "FVPQ1__n__<encapsulated key>__n__<ciphertext>"

// Decrypt a message
const decrypted = await pqDecrypt(keyPair.privateKey, encrypted);
console.log(new TextDecoder().decode(decrypted)); // "Secret message"

// You can also use the raw format for the encrypted data
const encryptedRaw = await pqEncrypt(keyPair.publicKey, message, "raw");
// { version: "FVPQ1", enc: string, ciphertext: string }
```

#### Key Features

- **Hybrid security**: X-Wing combines ML-KEM-768 with X25519
- **Fresh encapsulation per message**: no nonce on the wire; HPKE derives it from the KEM shared secret
- **Tamper-evident version tag**: `FVPQ1` is bound as AEAD associated data, so a modified tag fails decryption
- **Strict parsing**: only canonical (standard alphabet, padded) base64 parts are accepted, and malformed input is rejected before any KEM work
- **Size**: each ciphertext carries a 1120-byte encapsulated key plus a 16-byte authentication tag

### Identity PQ Primitives

Pure functions for moving an identity's public key onto X-Wing and deriving deterministic PQ seeds. Byte formats and frozen invariants are documented in [docs/architecture/identity-pq.md](docs/architecture/identity-pq.md).

```typescript
import {
  deriveIdentityPqKeyPair,
  derivePortalPqSeed,
  encodeIdentityPublicKey,
  decodeIdentityPublicKey,
  matchesOnchainIdentityKey,
} from "@fileverse/crypto/identity";
import { generatePqKeyPair } from "@fileverse/crypto/pq";

// Identity key pair from the account's base64 argon2id hash and salt
const identity = await deriveIdentityPqKeyPair(ag2Hash, salt);

// Onchain public key blob: "FVPQID1" tag + 1216-byte X-Wing public key (1223 bytes)
const blob = encodeIdentityPublicKey(identity.publicKey);

// Decode either format
const decoded = decodeIdentityPublicKey(blob);
// { format: "pq", publicKey: Uint8Array } or { format: "rsa", spki: Uint8Array }

// Login-time drift guard: false means stop and decrypt nothing
const matches = matchesOnchainIdentityKey(identity.publicKey, blob);

// Portal key pair from the portal's base64 owner secret and its address
const portalSeed = derivePortalPqSeed(ownerSecretBase64, portalAddress);
const portalKeyPair = await generatePqKeyPair(portalSeed);
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

### PQ Module

Import from `@fileverse/crypto/pq`. The root package also re-exports `generatePqKeyPair`, `pqEncrypt`, `pqDecrypt` and `parsePqCipherString`; `getPublicKey` at the root is the ECIES one.

#### `generatePqKeyPair<E extends EncodingType = "bytes">(seed?: Uint8Array, encoding?: E): Promise<PqKeyPairType<E>>`

Generates an X-Wing key pair. The private key is the 32-byte seed; the public key is 1216 bytes.

- **Parameters:**
  - `seed`: Optional. A 32-byte seed for deterministic generation. Random if omitted.
  - `encoding`: Optional. The encoding type to use ("base64" or "bytes"). Default: "bytes".
- **Returns:** A promise resolving to an object containing `publicKey` and `privateKey` in the specified encoding.
- **Throws:** Error if the seed is not 32 bytes.

#### `getPublicKey<E extends EncodingType = "bytes">(privateKey: Uint8Array, encoding?: E): Promise<EncodedReturnType<E>>`

Recomputes the X-Wing public key from a 32-byte private key.

- **Throws:** Error if the private key is not 32 bytes.

#### `pqEncrypt<T extends CipherTextFormat = "base64">(publicKey: Uint8Array, message: Uint8Array, returnFormat?: T): Promise<T extends "raw" ? PqCipher : string>`

Encrypts data with HPKE single-shot seal over X-Wing.

- **Parameters:**
  - `publicKey`: The 1216-byte X-Wing public key.
  - `message`: The data to encrypt.
  - `returnFormat`: Optional. "base64" returns `FVPQ1__n__<enc>__n__<ciphertext>`; "raw" returns a `PqCipher` object. Default: "base64".
- **Returns:** A promise resolving to the encrypted data in the specified format.

#### `pqDecrypt(privateKey: Uint8Array, encryptedData: PqCipher | string): Promise<Uint8Array>`

Decrypts data produced by `pqEncrypt`.

- **Parameters:**
  - `privateKey`: The 32-byte private key.
  - `encryptedData`: The encrypted string or `PqCipher` object.
- **Returns:** A promise resolving to the decrypted data as a Uint8Array.
- **Throws:** Error on a wrong key length, an unsupported version, malformed or non-canonical parts, or authentication failure.

#### `parsePqCipherString(concatenatedData: string): PqCipher`

Splits and validates a `pqEncrypt` string into its `version`, `enc` and `ciphertext` parts.

#### Constants

- `VERSION`: `"FVPQ1"`, the wire tag prefixed to every ciphertext.
- `INFO`: the HPKE application context (`"FILEVERSE-PQ-HPKE-XWING-v1"`).
- `SUITE`: `{ kem: "X-Wing", kdf: "HKDF-SHA256", aead: "AES-256-GCM" }`.

### Identity Module

Import from `@fileverse/crypto/identity`. All functions are pure: no storage, no network, no chain access.

#### `encodeIdentityPublicKey(xwingPublicKey: Uint8Array): Uint8Array`

Encodes an X-Wing public key as the 1223-byte identity blob (`"FVPQID1"` + 1216-byte key).

- **Throws:** Error if the key is not 1216 bytes.

#### `decodeIdentityPublicKey(bytes: Uint8Array): DecodedIdentityPublicKey`

Decodes an identity public key blob of either generation.

- **Returns:** `{ format: "pq", publicKey }` for a tagged 1223-byte blob, or `{ format: "rsa", spki }` for a legacy RSA SPKI DER blob.
- **Throws:** Error on a tagged blob of the wrong length or an unknown format.

#### `deriveIdentityPqSeed(ag2Hash: string, salt: Uint8Array): Uint8Array`

Derives the 32-byte identity seed with HKDF-SHA256 (info `"PQ_IDENTITY_KEY"`). The input key material is the UTF-8 bytes of the base64 `ag2Hash` string, not the decoded hash, matching the existing `MASTER_KEY` / `SIGNING_KEY` / `AGENT_KEY` derivations.

- **Parameters:**
  - `ag2Hash`: Standard padded base64 of a 32-byte argon2id hash.
  - `salt`: The identity salt. Must be non-empty.
- **Throws:** Error if `ag2Hash` is not strict base64 of 32 bytes or `salt` is empty.

#### `deriveIdentityPqKeyPair(ag2Hash: string, salt: Uint8Array): Promise<PqKeyPairBytes>`

`deriveIdentityPqSeed` followed by `generatePqKeyPair(seed)`.

#### `derivePortalPqSeed(ownerSecretBase64: string, portalAddress: string): Uint8Array`

Derives a 32-byte portal seed with HKDF-SHA256: key material is the decoded owner secret, salt is the UTF-8 bytes of the lowercased portal address, info is `"PQ_PORTAL_KEY"`.

- **Parameters:**
  - `ownerSecretBase64`: Standard padded base64 of the portal's 64-byte ed25519 secret.
  - `portalAddress`: A `0x`-prefixed 20-byte hex address, in any casing.
- **Throws:** Error if either input is malformed.

#### `matchesOnchainIdentityKey(derivedPublicKey: Uint8Array, onchainAccountPublicKey: Uint8Array): boolean`

Constant-time check that a derived X-Wing public key matches the onchain blob. Returns `false` for legacy RSA blobs and malformed input. A `false` on a rotated account means derivation drift: callers must stop and decrypt nothing.

#### Constants

`IDENTITY_PQ_TAG`, `HKDF_INFO_IDENTITY_PQ`, `HKDF_INFO_PORTAL_PQ`, `XWING_PUBLIC_KEY_LEN`, `SEED_LEN`, `AG2_HASH_DECODED_LEN`, `OWNER_SECRET_DECODED_LEN`. These are frozen: changing any of them orphans existing keys.

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
- [@hpke/core](https://github.com/dajiaji/hpke-js) - For HPKE (RFC 9180)
- [@hpke/hybridkem-x-wing](https://github.com/dajiaji/hpke-js) - For the X-Wing hybrid KEM
- [mlkem](https://github.com/dajiaji/crystals-kyber-js) - For ML-KEM, used by X-Wing

## Audits

| Auditor | Report | Date | Scope | Findings |
| --- | --- | --- | --- | --- |
| Nethermind Security | [NM-1025](audits/NM-1025-fileverse-crypto-pqc.pdf) | October 8, 2026 | All modules in `src/`: `pq`, `identity`, `ecies`, `webcrypto`, `nacl`, `argon`, `kdf`, `utils` | None (0 critical, high, medium, low or informational) |

- The review covered commit `37b549d` of the pre-release `@fileverse/crypto-pqc` package. The `src/` tree in v0.0.24 is identical to it apart from one comment naming the package.
- In `src/kdf/core.ts` only `deriveHKDFKey` was in scope. The PBKDF2 and AES-CBC helpers there are deprecated and were not reviewed.
- Nethermind rated both the documentation and the test suite High. The `pq` module has 100% test coverage and the `identity` module 100% line and 97% branch coverage.

## Security Considerations

- The library was reviewed by Nethermind Security with no findings (see [Audits](#audits)). Changes made after v0.0.24 are not covered by that review.
- The PQ module pins `@hpke/hybridkem-x-wing` 0.7.0 (draft-connolly-cfrg-xwing-kem-06). Seeded key pairs depend on that version's key generation, so upgrade it only after the X-Wing known-answer tests pass.
- Always keep private keys secure and never expose them in client-side code.
- The library doesn't handle key storage - use appropriate secure storage mechanisms for your platform.

## Development

### Prerequisites

- Node.js (v18+)
- npm or yarn

### Setup

```bash
# Clone the repository
git clone https://github.com/fileverse/fileverse-cryptography.git
cd fileverse-cryptography

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

# Recompute the pinned identity derivation vectors with independent HKDF implementations
npm run capture:vectors
```

## Browser Compatibility

This library supports all modern browsers that implement the Web Crypto API and TextEncoder/TextDecoder APIs:

- Chrome/Edge 60+
- Firefox 55+
- Safari 11+
- iOS Safari 11+

## License

GNU AGPL v3 (see [LICENSE.md](LICENSE.md))
