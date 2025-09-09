import { describe, it, expect } from "vitest";
import { rsaEncrypt, rsaDecrypt, aesEncrypt, aesDecrypt } from "../core";
import {
  generateRSAKeyPair,
  generateAESKey,
  toAESKey,
  exportAESKey,
} from "../keys";
import { toBytes } from "../../utils/encoding";

describe("RSA encryption/decryption", () => {
  it("should encrypt and decrypt messages with RSA", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const message = new TextEncoder().encode("Hello, RSA encryption!");

    const encrypted = await rsaEncrypt(keyPair.publicKey, message, "base64");
    expect(typeof encrypted).toBe("string");

    const decrypted = await rsaDecrypt(keyPair.privateKey, toBytes(encrypted));
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe("Hello, RSA encryption!");
  });

  it("should encrypt with bytes encoding", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const message = new TextEncoder().encode("Bytes encoding test");

    const encrypted = await rsaEncrypt(keyPair.publicKey, message, "bytes");
    expect(encrypted instanceof Uint8Array).toBe(true);

    const decrypted = await rsaDecrypt(
      keyPair.privateKey,
      encrypted as Uint8Array
    );
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe("Bytes encoding test");
  });

  it("should use base64 encoding by default", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const message = new TextEncoder().encode("Default encoding test");

    const encrypted = await rsaEncrypt(keyPair.publicKey, message);
    expect(typeof encrypted).toBe("string");

    const decrypted = await rsaDecrypt(keyPair.privateKey, toBytes(encrypted));
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe("Default encoding test");
  });

  it("should handle empty messages", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const emptyMessage = new Uint8Array(0);

    const encrypted = await rsaEncrypt(
      keyPair.publicKey,
      emptyMessage,
      "bytes"
    );
    const decrypted = await rsaDecrypt(
      keyPair.privateKey,
      encrypted as Uint8Array
    );

    expect(decrypted).toEqual(emptyMessage);
    expect(decrypted.length).toBe(0);
  });

  it("should produce different ciphertexts for the same message", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const message = new TextEncoder().encode("Same message");

    const encrypted1 = await rsaEncrypt(keyPair.publicKey, message, "base64");
    const encrypted2 = await rsaEncrypt(keyPair.publicKey, message, "base64");

    expect(encrypted1).not.toBe(encrypted2); // Should be different due to nonce

    const decrypted1 = await rsaDecrypt(
      keyPair.privateKey,
      toBytes(encrypted1)
    );
    const decrypted2 = await rsaDecrypt(
      keyPair.privateKey,
      toBytes(encrypted2)
    );

    expect(new TextDecoder().decode(decrypted1)).toBe("Same message");
    expect(new TextDecoder().decode(decrypted2)).toBe("Same message");
  });

  it("should fail with wrong private key", async () => {
    const keyPair1 = await generateRSAKeyPair(2048, "bytes");
    const keyPair2 = await generateRSAKeyPair(2048, "bytes");
    const message = new TextEncoder().encode("Secret message");

    const encrypted = await rsaEncrypt(keyPair1.publicKey, message, "bytes");

    await expect(
      rsaDecrypt(keyPair2.privateKey, encrypted as Uint8Array)
    ).rejects.toThrow();
  });

  it("should handle binary data correctly", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const binaryData = new Uint8Array([0, 1, 2, 3, 255, 254, 253, 128, 127]);

    const encrypted = await rsaEncrypt(keyPair.publicKey, binaryData, "bytes");
    const decrypted = await rsaDecrypt(
      keyPair.privateKey,
      encrypted as Uint8Array
    );

    expect(decrypted).toEqual(binaryData);
  });

  it("should work with different key sizes", async () => {
    const testKeySizes = [2048, 3072, 4096];

    for (const keySize of testKeySizes) {
      const keyPair = await generateRSAKeyPair(keySize, "bytes");
      const message = new TextEncoder().encode(`Test with ${keySize} bit key`);

      const encrypted = await rsaEncrypt(keyPair.publicKey, message, "base64");
      const decrypted = await rsaDecrypt(
        keyPair.privateKey,
        toBytes(encrypted)
      );
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(`Test with ${keySize} bit key`);
    }
  });
});

describe("AES encryption/decryption", () => {
  it("should encrypt and decrypt messages with AES", async () => {
    const key = await generateAESKey(256);
    const message = new TextEncoder().encode("Hello, AES encryption!");

    const encrypted = await aesEncrypt(key, message, "base64");
    expect(typeof encrypted).toBe("string");

    const decrypted = await aesDecrypt(key, toBytes(encrypted));
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe("Hello, AES encryption!");
  });

  it("should encrypt with bytes encoding", async () => {
    const key = await generateAESKey(256);
    const message = new TextEncoder().encode("Bytes encoding test");

    const encrypted = await aesEncrypt(key, message, "bytes");
    expect(encrypted instanceof Uint8Array).toBe(true);

    const decrypted = await aesDecrypt(key, encrypted as Uint8Array);
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe("Bytes encoding test");
  });

  it("should use bytes encoding by default", async () => {
    const key = await generateAESKey(256);
    const message = new TextEncoder().encode("Default encoding test");

    const encrypted = await aesEncrypt(key, message);
    expect(encrypted instanceof Uint8Array).toBe(true);

    const decrypted = await aesDecrypt(key, encrypted as Uint8Array);
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe("Default encoding test");
  });

  it("should handle empty messages", async () => {
    const key = await generateAESKey(256);
    const emptyMessage = new Uint8Array(0);

    const encrypted = await aesEncrypt(key, emptyMessage, "bytes");
    const decrypted = await aesDecrypt(key, encrypted as Uint8Array);

    expect(decrypted).toEqual(emptyMessage);
    expect(decrypted.length).toBe(0);
  });

  it("should produce different ciphertexts for the same message", async () => {
    const key = await generateAESKey(256);
    const message = new TextEncoder().encode("Same message");

    const encrypted1 = await aesEncrypt(key, message, "base64");
    const encrypted2 = await aesEncrypt(key, message, "base64");

    expect(encrypted1).not.toBe(encrypted2); // Should be different due to random nonce

    const decrypted1 = await aesDecrypt(key, toBytes(encrypted1));
    const decrypted2 = await aesDecrypt(key, toBytes(encrypted2));

    expect(new TextDecoder().decode(decrypted1)).toBe("Same message");
    expect(new TextDecoder().decode(decrypted2)).toBe("Same message");
  });

  it("should fail with wrong key", async () => {
    const key1 = await generateAESKey(256);
    const key2 = await generateAESKey(256);
    const message = new TextEncoder().encode("Secret message");

    const encrypted = await aesEncrypt(key1, message, "bytes");

    await expect(aesDecrypt(key2, encrypted as Uint8Array)).rejects.toThrow();
  });

  it("should handle large messages efficiently", async () => {
    const key = await generateAESKey(256);
    const largeMessage = new Uint8Array(1024 * 500); // 500KB
    largeMessage.fill(42); // Fill with test data

    const encrypted = await aesEncrypt(key, largeMessage, "bytes");
    const decrypted = await aesDecrypt(key, encrypted as Uint8Array);

    expect(decrypted).toEqual(largeMessage);
  });

  it("should handle binary data correctly", async () => {
    const key = await generateAESKey(256);
    const binaryData = new Uint8Array([0, 1, 2, 3, 255, 254, 253, 128, 127]);

    const encrypted = await aesEncrypt(key, binaryData, "bytes");
    const decrypted = await aesDecrypt(key, encrypted as Uint8Array);

    expect(decrypted).toEqual(binaryData);
  });

  it("should work with different key sizes", async () => {
    const testKeySizes = [128, 192, 256];

    for (const keySize of testKeySizes) {
      const key = await generateAESKey(keySize);
      const message = new TextEncoder().encode(`Test with ${keySize} bit key`);

      const encrypted = await aesEncrypt(key, message, "base64");
      const decrypted = await aesDecrypt(key, toBytes(encrypted));
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(`Test with ${keySize} bit key`);
    }
  });

  it("should work with imported keys", async () => {
    const originalKey = await generateAESKey(256);
    const keyBytes = await exportAESKey(originalKey, "bytes");
    const importedKey = await toAESKey(keyBytes as Uint8Array);

    const message = new TextEncoder().encode("Test with imported key");

    const encrypted = await aesEncrypt(originalKey, message, "base64");
    const decrypted = await aesDecrypt(importedKey, toBytes(encrypted));
    const decryptedText = new TextDecoder().decode(decrypted);

    expect(decryptedText).toBe("Test with imported key");
  });

  it("should handle corrupted ciphertext gracefully", async () => {
    const key = await generateAESKey(256);
    const message = new TextEncoder().encode("Test message");

    const encrypted = (await aesEncrypt(key, message, "bytes")) as Uint8Array;

    // Corrupt the ciphertext
    const corrupted = new Uint8Array(encrypted);
    corrupted[corrupted.length - 1] ^= 0xff; // Flip bits in the last byte

    await expect(aesDecrypt(key, corrupted)).rejects.toThrow();
  });

  it("should handle truncated ciphertext gracefully", async () => {
    const key = await generateAESKey(256);
    const message = new TextEncoder().encode("Test message");

    const encrypted = (await aesEncrypt(key, message, "bytes")) as Uint8Array;

    // Truncate the ciphertext
    const truncated = encrypted.slice(0, encrypted.length - 10);

    await expect(aesDecrypt(key, truncated)).rejects.toThrow();
  });
});
