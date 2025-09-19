import { describe, it, expect } from "vitest";
import { secretBoxEncrypt, secretBoxDecrypt } from "../core";
import { generateSecretBoxKey } from "../keys";
import { SEPARATOR } from "../../constants";

describe("NaCl Secret Box Core Functionality", () => {
  const testMessage = "Hello, secret world!";
  const messageBytes = new TextEncoder().encode(testMessage);

  describe("secretBoxEncrypt", () => {
    it("should encrypt a message and return a base64 string", () => {
      const key = generateSecretBoxKey();
      const encrypted = secretBoxEncrypt(key, messageBytes);

      expect(typeof encrypted).toBe("string");
      expect(encrypted.split(SEPARATOR).length).toBe(2);
    });

    it("should encrypt with URL-safe base64 when specified", () => {
      const key = generateSecretBoxKey();
      const encrypted = secretBoxEncrypt(key, messageBytes, true);

      expect(typeof encrypted).toBe("string");
      expect(encrypted.split(SEPARATOR).length).toBe(2);
    });

    it("should produce different ciphertexts for the same plaintext", () => {
      const key = generateSecretBoxKey();

      const encrypted1 = secretBoxEncrypt(key, messageBytes);
      const encrypted2 = secretBoxEncrypt(key, messageBytes);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it("should throw error for invalid key length", () => {
      const invalidKey = new Uint8Array(16); // Wrong length (should be 32)

      expect(() => secretBoxEncrypt(invalidKey, messageBytes)).toThrow(
        "Invalid key length"
      );
    });
  });

  describe("secretBoxDecrypt", () => {
    it("should correctly decrypt a message", () => {
      const key = generateSecretBoxKey();
      const encrypted = secretBoxEncrypt(key, messageBytes);
      const decrypted = secretBoxDecrypt(key, encrypted);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(testMessage);
    });

    it("should handle URL-safe encrypted messages", () => {
      const key = generateSecretBoxKey();
      const encrypted = secretBoxEncrypt(key, messageBytes, true);
      const decrypted = secretBoxDecrypt(key, encrypted);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(testMessage);
    });

    it("should throw error for invalid key length", () => {
      const key = generateSecretBoxKey();
      const encrypted = secretBoxEncrypt(key, messageBytes);
      const invalidKey = new Uint8Array(16); // Wrong length

      expect(() => secretBoxDecrypt(invalidKey, encrypted)).toThrow(
        "Invalid key length"
      );
    });

    it("should throw error for invalid encrypted message format", () => {
      const key = generateSecretBoxKey();
      const invalidEncrypted = "not-a-valid-encrypted-message";

      expect(() => secretBoxDecrypt(key, invalidEncrypted)).toThrow(
        "Invalid encrypted message"
      );
    });

    it("should throw error for corrupted nonce", () => {
      const key = generateSecretBoxKey();
      const encrypted = secretBoxEncrypt(key, messageBytes);
      const corruptedEncrypted =
        "corrupted-nonce" + SEPARATOR + encrypted.split(SEPARATOR)[1];

      expect(() => secretBoxDecrypt(key, corruptedEncrypted)).toThrow();
    });

    it("should throw error for authentication failure", () => {
      const key1 = generateSecretBoxKey();
      const key2 = generateSecretBoxKey();
      const encrypted = secretBoxEncrypt(key1, messageBytes);

      expect(() => secretBoxDecrypt(key2, encrypted)).toThrow(
        "Could not decrypt message"
      );
    });
  });

  describe("Encryption/Decryption Round Trip", () => {
    it("should correctly round-trip various message types", () => {
      const key = generateSecretBoxKey();

      const testCases = [
        { name: "Empty message", data: new Uint8Array(0) },
        { name: "Short text", data: new TextEncoder().encode("Hi!") },
        { name: "Binary data", data: new Uint8Array([1, 2, 3, 255, 0]) },
        {
          name: "Unicode text",
          data: new TextEncoder().encode("Hello 🌍 世界"),
        },
      ];

      for (const { name, data } of testCases) {
        const encrypted = secretBoxEncrypt(key, data);
        const decrypted = secretBoxDecrypt(key, encrypted);

        expect(new Uint8Array(decrypted)).toEqual(data);
      }
    });

    it("should maintain data integrity for all byte values", () => {
      const key = generateSecretBoxKey();
      const allBytes = new Uint8Array(256);

      for (let i = 0; i < 256; i++) {
        allBytes[i] = i;
      }

      const encrypted = secretBoxEncrypt(key, allBytes);
      const decrypted = secretBoxDecrypt(key, encrypted);

      expect(decrypted).toEqual(allBytes);
    });
  });
});
