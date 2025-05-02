import { describe, it, expect } from "vitest";
import { generateRSAKeyPair, toRSAKey, DEFAULT_RSA_KEY_SIZE } from "../keys";
import { toBytes } from "../../utils/encoding-utils";

describe("RSA Key Management", () => {
  // Use smaller key size for faster tests
  const TEST_KEY_SIZE = 1024;

  describe("generateRSAKeyPair", () => {
    it("should generate a key pair with base64 encoding by default", async () => {
      const keyPair = await generateRSAKeyPair(TEST_KEY_SIZE);

      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      expect(typeof keyPair.publicKey).toBe("string");
      expect(typeof keyPair.privateKey).toBe("string");
    });

    it("should generate a key pair with bytes encoding when specified", async () => {
      const keyPair = await generateRSAKeyPair(TEST_KEY_SIZE, "bytes");

      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      expect(keyPair.publicKey instanceof Uint8Array).toBe(true);
      expect(keyPair.privateKey instanceof Uint8Array).toBe(true);
    });

    it("should generate different key pairs on each call", async () => {
      const keyPair1 = await generateRSAKeyPair(TEST_KEY_SIZE);
      const keyPair2 = await generateRSAKeyPair(TEST_KEY_SIZE);

      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    });

    it("should respect the key size parameter", async () => {
      const smallKeyPair = await generateRSAKeyPair(TEST_KEY_SIZE, "bytes");
      const largeKeyPair = await generateRSAKeyPair(TEST_KEY_SIZE * 2, "bytes");

      // The byteLength of the larger key should be greater than the smaller one
      expect(largeKeyPair.publicKey.byteLength).toBeGreaterThan(
        smallKeyPair.publicKey.byteLength
      );
      expect(largeKeyPair.privateKey.byteLength).toBeGreaterThan(
        smallKeyPair.privateKey.byteLength
      );
    });

    it("should use DEFAULT_RSA_KEY_SIZE when no size is specified", async () => {
      const keyPair1 = await generateRSAKeyPair(undefined, "bytes");
      const keyPair2 = await generateRSAKeyPair(DEFAULT_RSA_KEY_SIZE, "bytes");

      // Both keys should be approximately the same size
      expect(keyPair1.publicKey.byteLength).toBeGreaterThan(
        DEFAULT_RSA_KEY_SIZE / 10
      ); // Public key is roughly 1/8 of key size in bits
      expect(keyPair1.privateKey.byteLength).toBeGreaterThan(
        DEFAULT_RSA_KEY_SIZE / 10
      );

      expect(
        Math.abs(keyPair1.publicKey.byteLength - keyPair2.publicKey.byteLength)
      ).toBeLessThan(50);
      expect(
        Math.abs(
          keyPair1.privateKey.byteLength - keyPair2.privateKey.byteLength
        )
      ).toBeLessThan(50);
    });
  });

  describe("toRSAKey", () => {
    it("should import a public key in SPKI format", async () => {
      const keyPair = await generateRSAKeyPair(TEST_KEY_SIZE, "bytes");
      const publicKeyBytes = keyPair.publicKey;

      const importedKey = await toRSAKey(publicKeyBytes, "spki");

      expect(importedKey).toBeDefined();
      expect(importedKey.type).toBe("public");
      expect(importedKey.algorithm.name).toBe("RSA-OAEP");
      expect(importedKey.usages).toContain("encrypt");
      expect(importedKey.usages).not.toContain("decrypt");
    });

    it("should import a private key in PKCS8 format", async () => {
      const keyPair = await generateRSAKeyPair(TEST_KEY_SIZE, "bytes");
      const privateKeyBytes = keyPair.privateKey;

      const importedKey = await toRSAKey(privateKeyBytes, "pkcs8");

      expect(importedKey).toBeDefined();
      expect(importedKey.type).toBe("private");
      expect(importedKey.algorithm.name).toBe("RSA-OAEP");
      expect(importedKey.usages).toContain("decrypt");
      expect(importedKey.usages).not.toContain("encrypt");
    });

    it("should handle base64 encoded keys after conversion to bytes", async () => {
      const keyPair = await generateRSAKeyPair(TEST_KEY_SIZE);

      // Convert base64 encoded keys to bytes
      const publicKeyBytes = toBytes(keyPair.publicKey);
      const privateKeyBytes = toBytes(keyPair.privateKey);

      // Try to import both keys
      const importedPublicKey = await toRSAKey(publicKeyBytes, "spki");
      const importedPrivateKey = await toRSAKey(privateKeyBytes, "pkcs8");

      expect(importedPublicKey.type).toBe("public");
      expect(importedPrivateKey.type).toBe("private");
    });

    it("should reject invalid key data", async () => {
      const invalidKeyData = new Uint8Array([1, 2, 3, 4, 5]);

      await expect(toRSAKey(invalidKeyData, "spki")).rejects.toThrow();
      await expect(toRSAKey(invalidKeyData, "pkcs8")).rejects.toThrow();
    });
  });

  describe("Key Import/Export Cycle", () => {
    it("should successfully export and reimport keys", async () => {
      // Generate key pair
      const keyPair = await generateRSAKeyPair(TEST_KEY_SIZE, "bytes");

      // Import keys
      const publicKey = await toRSAKey(keyPair.publicKey, "spki");
      const privateKey = await toRSAKey(keyPair.privateKey, "pkcs8");

      // Basic validation
      expect(publicKey.type).toBe("public");
      expect(privateKey.type).toBe("private");

      // Try encrypting/decrypting to validate the keys work
      const testData = new TextEncoder().encode("test data");

      // Encrypt with public key
      const encryptedData = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        testData
      );

      // Decrypt with private key
      const decryptedData = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedData
      );

      // Verify decryption works
      const decryptedText = new TextDecoder().decode(decryptedData);
      expect(decryptedText).toBe("test data");
    });
  });
});
