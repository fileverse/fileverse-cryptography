import { describe, it, expect } from "vitest";
import { generateECKeyPair, deriveSharedSecret } from "../keys";
import { bytesToBase64 } from "../../utils";

describe("ECIES Key Functions", () => {
  describe("generateECKeyPair", () => {
    it("should generate a key pair with bytes encoding by default", () => {
      const keyPair = generateECKeyPair();

      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      expect(keyPair.publicKey instanceof Uint8Array).toBe(true);
      expect(keyPair.privateKey instanceof Uint8Array).toBe(true);
    });

    it("should generate a key pair with base64 encoding when specified", () => {
      const keyPair = generateECKeyPair("base64");

      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      expect(typeof keyPair.publicKey).toBe("string");
      expect(typeof keyPair.privateKey).toBe("string");
    });

    it("should generate different key pairs on each call", () => {
      const keyPair1 = generateECKeyPair();
      const keyPair2 = generateECKeyPair();

      // Need to use toEqual for Uint8Array comparison, not toBe (reference equality)
      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
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

      // Use toEqual for Uint8Array comparison, not toBe
      expect(aliceSharedSecret).toEqual(bobSharedSecret);
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

      // Use toEqual for Uint8Array comparison
      expect(sharedSecret1).not.toEqual(sharedSecret2);
    });

    it("should accept both string and Uint8Array inputs", () => {
      // Generate base64 keys for string testing
      const keyPair1 = generateECKeyPair("base64");
      const keyPair2 = generateECKeyPair("base64");

      // Generate bytes keys for Uint8Array testing
      const keyPair3 = generateECKeyPair();
      const keyPair4 = generateECKeyPair();

      // Test different combinations of input types
      const secret1 = deriveSharedSecret(
        keyPair1.privateKey,
        keyPair2.publicKey
      );

      const secret2 = deriveSharedSecret(
        keyPair3.privateKey,
        keyPair2.publicKey
      );

      const secret3 = deriveSharedSecret(
        keyPair1.privateKey,
        keyPair4.publicKey
      );

      const secret4 = deriveSharedSecret(
        keyPair3.privateKey,
        keyPair4.publicKey
      );

      // All should produce Uint8Array results by default
      expect(secret1 instanceof Uint8Array).toBe(true);
      expect(secret2 instanceof Uint8Array).toBe(true);
      expect(secret3 instanceof Uint8Array).toBe(true);
      expect(secret4 instanceof Uint8Array).toBe(true);
    });

    it("should return the shared secret in base64 format when specified", () => {
      const keyPair1 = generateECKeyPair();
      const keyPair2 = generateECKeyPair();

      const sharedSecret = deriveSharedSecret(
        keyPair1.privateKey,
        keyPair2.publicKey,
        "base64"
      );

      expect(typeof sharedSecret).toBe("string");
    });
  });
});
