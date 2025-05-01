import { describe, it, expect } from "vitest";
import { generateECKeyPair, deriveSharedSecret } from "../keys";
import { base64ToBytes, bytesToBase64 } from "../../utils";

describe("ECIES Key Functions", () => {
  describe("generateECKeyPair", () => {
    it("should generate a key pair with base64 encoding by default", () => {
      const keyPair = generateECKeyPair();

      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      expect(typeof keyPair.publicKey).toBe("string");
      expect(typeof keyPair.privateKey).toBe("string");
    });

    it("should generate a key pair with bytes encoding when specified", () => {
      const keyPair = generateECKeyPair("bytes");

      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      expect(keyPair.publicKey instanceof Uint8Array).toBe(true);
      expect(keyPair.privateKey instanceof Uint8Array).toBe(true);
    });

    it("should generate different key pairs on each call", () => {
      const keyPair1 = generateECKeyPair();
      const keyPair2 = generateECKeyPair();

      expect(keyPair1.publicKey).not.toBe(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toBe(keyPair2.privateKey);
    });
  });

  describe("deriveSharedSecret", () => {
    it("should derive the same shared secret from compatible key pairs", () => {
      const aliceKeyPair = generateECKeyPair();
      const bobKeyPair = generateECKeyPair();

      const aliceSharedSecret = deriveSharedSecret(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const bobSharedSecret = deriveSharedSecret(
        bobKeyPair.privateKey,
        aliceKeyPair.publicKey
      );

      expect(aliceSharedSecret).toBe(bobSharedSecret);
    });

    it("should derive different shared secrets from different key pairs", () => {
      const keyPair1 = generateECKeyPair();
      const keyPair2 = generateECKeyPair();
      const keyPair3 = generateECKeyPair();

      const sharedSecret1 = deriveSharedSecret(
        keyPair1.privateKey,
        keyPair2.publicKey
      );

      const sharedSecret2 = deriveSharedSecret(
        keyPair1.privateKey,
        keyPair3.publicKey
      );

      expect(sharedSecret1).not.toBe(sharedSecret2);
    });

    it("should accept both string and Uint8Array inputs", () => {
      const keyPair1 = generateECKeyPair();
      const keyPair2 = generateECKeyPair();

      // Convert to bytes for testing
      const privateKeyBytes = base64ToBytes(keyPair1.privateKey);
      const publicKeyBytes = base64ToBytes(keyPair2.publicKey);

      // Test different combinations of input types
      const secret1 = deriveSharedSecret(
        keyPair1.privateKey,
        keyPair2.publicKey
      );
      const secret2 = deriveSharedSecret(privateKeyBytes, keyPair2.publicKey);
      const secret3 = deriveSharedSecret(keyPair1.privateKey, publicKeyBytes);
      const secret4 = deriveSharedSecret(privateKeyBytes, publicKeyBytes);

      expect(secret1).toBe(secret2);
      expect(secret2).toBe(secret3);
      expect(secret3).toBe(secret4);
    });

    it("should return the shared secret in bytes format when specified", () => {
      const keyPair1 = generateECKeyPair();
      const keyPair2 = generateECKeyPair();

      const sharedSecret = deriveSharedSecret(
        keyPair1.privateKey,
        keyPair2.publicKey,
        "bytes"
      );

      expect(sharedSecret instanceof Uint8Array).toBe(true);
    });
  });
});
