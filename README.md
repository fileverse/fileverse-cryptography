# fileverse-crypto

A library providing cryptographic functions, including:

- ECIES (Elliptic Curve Integrated Encryption Scheme) using secp256k1 and AES-GCM.

## Installation

```bash
npm install fileverse-crypto
# or
yarn add fileverse-crypto
```

## Usage

### ECIES (secp256k1 / AES-GCM)

```typescript
import {
  generateKeyPair,
  encrypt,
  decrypt,
  type EciesCiphertext,
} from "fileverse-crypto";
import { TextEncoder, TextDecoder } from "util"; // Node.js specific for example

async function eciesExample() {
  // Generate recipient key pair
  const recipientKeys = generateKeyPair();
  console.log("Recipient Private Key:", recipientKeys.privateKey);
  console.log("Recipient Public Key:", recipientKeys.publicKey);

  // Message to encrypt
  const message = new TextEncoder().encode("Hello, ECIES!");

  // Encrypt the message for the recipient
  const encryptedData: EciesCiphertext = await encrypt(
    recipientKeys.publicKey,
    message
  );
  console.log("Encrypted Data:", encryptedData);

  // Decrypt the message using the recipient's private key
  const decryptedMessage: Uint8Array | null = await decrypt(
    recipientKeys.privateKey,
    encryptedData
  );

  if (decryptedMessage) {
    console.log(
      "Decrypted Message:",
      new TextDecoder().decode(decryptedMessage)
    );
  } else {
    console.error("Decryption failed!");
  }
}

eciesExample().catch(console.error);
```

## Building

```bash
npm run build
```

## Publishing

Make sure to update the version in `
