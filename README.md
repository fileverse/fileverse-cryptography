# Fileverse Crypto

A comprehensive, type-safe cryptographic library for JavaScript/TypeScript applications. This library provides a set of easy-to-use cryptographic primitives with a focus on security, type safety, and flexibility.

## Features

- **ECIES** (Elliptic Curve Integrated Encryption Scheme) for asymmetric encryption
- **HKDF** (HMAC-based Key Derivation Function) for secure key derivation
- **Encoding Utilities** for consistent data format handling
- **Type-Safe API** with TypeScript generics for encoding types
- **Cross-platform** compatible with Node.js and modern browsers

## Installation

```bash
npm install fileverse-crypto
```

## Usage

### ECIES

Elliptic Curve Integrated Encryption Scheme for secure asymmetric encryption.

```typescript
import {
  generateECKeyPair,
  eciesEncrypt,
  eciesDecrypt,
} from "fileverse-crypto/ecies";

// Generate a key pair
const keyPair = generateECKeyPair();
// { publicKey: "base64-encoded-string", privateKey: "base64-encoded-string" }

// Or generate with bytes encoding
const bytesKeyPair = generateECKeyPair("bytes");
// { publicKey: Uint8Array, privateKey: Uint8Array }

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
import { generateECKeyPair, deriveSharedSecret } from "fileverse-crypto/ecies";

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

### HKDF

HMAC-based Key Derivation Function for deriving secure cryptographic keys.

```typescript
import { deriveHKDFKey } from "fileverse-crypto/hkdf";

// Derive a key
const keyMaterial = "some-secure-key-material";
const salt = new TextEncoder().encode("salt-value");
const info = new TextEncoder().encode("context-info");

// Get key as Uint8Array (default)
const key = deriveHKDFKey(keyMaterial, salt, info);

// Or get key as base64 string
const keyBase64 = deriveHKDFKey(keyMaterial, salt, info, "base64");
```

### Encoding Utilities

Utilities for handling encoding conversions consistently.

```typescript
import {
  base64ToBytes,
  bytesToBase64,
  encodeData,
} from "fileverse-crypto/utils";

// Convert base64 to Uint8Array
const bytes = base64ToBytes("SGVsbG8gV29ybGQ=");

// Convert Uint8Array to base64
const base64 = bytesToBase64(new TextEncoder().encode("Hello World"));

// Generic encoding with type safety
const data = new TextEncoder().encode("Test data");
const bytesResult = encodeData(data, "bytes"); // Returns Uint8Array
const base64Result = encodeData(data, "base64"); // Returns string
```

## API Reference

### ECIES Module

#### `generateECKeyPair<E extends EncodingType = "base64">(encoding?: E): EciesKeyPairType<E>`

Generates an ECIES key pair with the specified encoding.

- **Parameters:**
  - `encoding`: Optional. The encoding type to use ("base64" or "bytes"). Default: "base64".
- **Returns:** An object containing `publicKey` and `privateKey` in the specified encoding.

#### `deriveSharedSecret<E extends EncodingType = "base64">(privateKey: Uint8Array | string, publicKey: Uint8Array | string, encoding?: E): EncodedReturnType<E>`

Derives a shared secret from a private key and a public key.

- **Parameters:**
  - `privateKey`: The private key (base64 string or Uint8Array).
  - `publicKey`: The public key (base64 string or Uint8Array).
  - `encoding`: Optional. The encoding type for the result. Default: "base64".
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

### HKDF Module

#### `deriveHKDFKey<E extends EncodingType = "bytes">(keyMaterial: string, salt: Uint8Array, info: Uint8Array, encoding?: E): EncodedReturnType<E>`

Derives a key using HKDF.

- **Parameters:**
  - `keyMaterial`: The key material.
  - `salt`: The salt.
  - `info`: The context info.
  - `encoding`: Optional. The encoding type for the result. Default: "bytes".
- **Returns:** The derived key in the specified encoding.

### Encoding Utilities

#### `base64ToBytes(base64: string): Uint8Array`

Converts a base64 string to a Uint8Array.

#### `bytesToBase64(bytes: Uint8Array, urlSafe = true): string`

Converts a Uint8Array to a base64 string.

- **Parameters:**
  - `bytes`: The bytes to convert.
  - `urlSafe`: Optional. Whether to use URL-safe base64 encoding. Default: true.
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
git clone https://github.com/fileverse/fileverse-crypto.git
cd fileverse-crypto

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

ISC
