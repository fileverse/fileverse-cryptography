import { describe, it, expect } from "vitest";
import {
  generateRandomAESKey,
  exportAESKey,
  aesEncrypt,
  aesDecrypt,
  toAESKey,
} from "../envelope-helpers";
import { toBytes } from "../../utils/encoding";

describe("RSA Envelope Helpers", () => {
  describe("AES Key Management", () => {
    it("should generate a valid AES key", async () => {
      const key = await generateRandomAESKey();

      expect(key).toBeDefined();
      expect(key.algorithm.name).toBe("AES-GCM");
      expect(key.type).toBe("secret");
      expect(key.extractable).toBe(true);
      expect(key.usages).toContain("encrypt");
      expect(key.usages).toContain("decrypt");
    });

    it("should export an AES key as bytes by default", async () => {
      const key = await generateRandomAESKey();
      const exportedKey = await exportAESKey(key);

      expect(exportedKey instanceof Uint8Array).toBe(true);
      expect(exportedKey.byteLength).toBe(32); // 256 bits = 32 bytes
    });

    it("should export an AES key as base64 when specified", async () => {
      const key = await generateRandomAESKey();
      const exportedKey = await exportAESKey(key, "base64");

      expect(typeof exportedKey).toBe("string");
      // Base64 encoding adds roughly 33% overhead
      expect(exportedKey.length).toBeGreaterThan(32);
    });

    it("should import bytes back to a valid AES key", async () => {
      const originalKey = await generateRandomAESKey();
      const exportedKeyBytes = await exportAESKey(originalKey);
      const importedKey = await toAESKey(exportedKeyBytes);

      expect(importedKey).toBeDefined();
      expect(importedKey.algorithm.name).toBe("AES-GCM");
      expect(importedKey.type).toBe("secret");
      expect(importedKey.extractable).toBe(true);
      expect(importedKey.usages).toContain("encrypt");
      expect(importedKey.usages).toContain("decrypt");
    });
  });

  describe("AES Encryption and Decryption", () => {
    it("should encrypt and decrypt a message successfully", async () => {
      const key = await generateRandomAESKey();
      const message = new TextEncoder().encode("Test AES encryption");

      const encrypted = await aesEncrypt(key, message);
      expect(encrypted instanceof Uint8Array).toBe(true);

      const decrypted = await aesDecrypt(key, encrypted);
      expect(decrypted instanceof Uint8Array).toBe(true);

      const decodedMessage = new TextDecoder().decode(decrypted);
      expect(decodedMessage).toBe("Test AES encryption");
    });

    it("should encrypt with bytes format by default", async () => {
      const key = await generateRandomAESKey();
      const message = new TextEncoder().encode("Message");

      const encrypted = await aesEncrypt(key, message);
      expect(encrypted instanceof Uint8Array).toBe(true);
    });

    it("should encrypt with base64 format when specified", async () => {
      const key = await generateRandomAESKey();
      const message = new TextEncoder().encode("Message");

      const encrypted = await aesEncrypt(key, message, "base64");
      expect(typeof encrypted).toBe("string");
    });

    it("should produce different ciphertexts for the same plaintext", async () => {
      const key = await generateRandomAESKey();
      const message = new TextEncoder().encode("Same message");

      const encrypted1 = await aesEncrypt(key, message, "base64");
      const encrypted2 = await aesEncrypt(key, message, "base64");

      expect(encrypted1).not.toBe(encrypted2);

      // But both should decrypt to the same message
      const decrypted1 = await aesDecrypt(key, toBytes(encrypted1));
      const decrypted2 = await aesDecrypt(key, toBytes(encrypted2));

      const decodedMessage1 = new TextDecoder().decode(decrypted1);
      const decodedMessage2 = new TextDecoder().decode(decrypted2);

      expect(decodedMessage1).toBe("Same message");
      expect(decodedMessage2).toBe("Same message");
    });

    it("should handle empty messages", async () => {
      const key = await generateRandomAESKey();
      const emptyMessage = new Uint8Array(0);

      const encrypted = await aesEncrypt(key, emptyMessage);
      const decrypted = await aesDecrypt(key, encrypted);

      expect(decrypted.byteLength).toBe(0);
    });

    it("should handle large messages", async () => {
      const key = await generateRandomAESKey();

      // Create a large message (100KB)
      const largeMessage = new Uint8Array(100 * 1024);
      for (let i = 0; i < largeMessage.length; i++) {
        largeMessage[i] = i % 256;
      }

      const encrypted = await aesEncrypt(key, largeMessage);
      const decrypted = await aesDecrypt(key, encrypted);

      expect(decrypted.byteLength).toBe(largeMessage.byteLength);

      // Verify content at random positions
      for (let i = 0; i < 10; i++) {
        const pos = Math.floor(Math.random() * largeMessage.length);
        expect(decrypted[pos]).toBe(largeMessage[pos]);
      }
    });

    it("should fail when decrypting with a different key", async () => {
      const key1 = await generateRandomAESKey();
      const key2 = await generateRandomAESKey();
      const message = new TextEncoder().encode("Secret message");

      const encrypted = await aesEncrypt(key1, message);

      await expect(aesDecrypt(key2, encrypted)).rejects.toThrow();
    });
  });

  describe("Full Key Export/Import Cycle", () => {
    it("should maintain encryption capability through export and import", async () => {
      // Generate and export a key
      const originalKey = await generateRandomAESKey();
      const exportedKeyBytes = await exportAESKey(originalKey);

      // Import the key again
      const importedKey = await toAESKey(exportedKeyBytes);

      // Test encryption/decryption with both keys
      const message = new TextEncoder().encode(
        "Testing key export/import cycle"
      );

      // Encrypt with original key
      const encrypted = await aesEncrypt(originalKey, message);

      // Decrypt with imported key
      const decrypted = await aesDecrypt(importedKey, encrypted);

      const decodedMessage = new TextDecoder().decode(decrypted);
      expect(decodedMessage).toBe("Testing key export/import cycle");
    });
  });
});
