import { describe, it, expect } from "vitest";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils";
import { CURVE } from "../../src/ecies/config"; // Adjust import path
import { generateKeyPair } from "../../src/ecies/keys"; // Adjust import path

describe("src/ecies/keys", () => {
  describe("generateKeyPair", () => {
    it("should generate a valid key pair", () => {
      const { publicKey, privateKey } = generateKeyPair();

      // Check if keys are hex strings
      expect(typeof publicKey).toBe("string");
      expect(typeof privateKey).toBe("string");

      // Check hex format (basic regex)
      expect(publicKey).toMatch(/^[0-9a-fA-F]+$/);
      expect(privateKey).toMatch(/^[0-9a-fA-F]+$/);

      // Check lengths (specific to secp256k1: 33 bytes compressed pubkey, 32 bytes privkey)
      // Public key hex length = 2 (prefix 0x02/0x03) + 32 * 2 (key data) = 66
      // Private key hex length = 32 * 2 = 64
      expect(publicKey.length).toBe(66); // Compressed public key length * 2 + 2 (prefix)
      expect(privateKey.length).toBe(64); // Private key length * 2

      // Verify the public key corresponds to the private key
      const privateKeyBytes = hexToBytes(privateKey);
      const expectedPublicKeyBytes = CURVE.getPublicKey(privateKeyBytes);
      expect(publicKey).toBe(bytesToHex(expectedPublicKeyBytes));
    });
  });
});
