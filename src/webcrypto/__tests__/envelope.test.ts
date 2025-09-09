import { describe, it, expect } from "vitest";
import { encryptEnvelope, decryptEnvelope } from "../envelope";
import { generateRSAKeyPair } from "../keys";

describe("Envelope encryption/decryption", () => {
  it("should encrypt and decrypt messages using envelope encryption", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const message = new TextEncoder().encode("Hello, envelope encryption!");

    const envelope = await encryptEnvelope(keyPair.publicKey, message);
    expect(typeof envelope).toBe("string");
    expect(envelope.includes("__n__")).toBe(true); // Contains separator

    const decrypted = await decryptEnvelope(keyPair.privateKey, envelope);
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe("Hello, envelope encryption!");
  });

  it("should handle large messages efficiently", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const largeMessage = new Uint8Array(1024 * 100); // 100KB
    largeMessage.fill(42); // Fill with test data

    const envelope = await encryptEnvelope(keyPair.publicKey, largeMessage);
    expect(typeof envelope).toBe("string");

    const decrypted = await decryptEnvelope(keyPair.privateKey, envelope);
    expect(decrypted).toEqual(largeMessage);
  });

  it("should work with empty messages", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const emptyMessage = new Uint8Array(0);

    const envelope = await encryptEnvelope(keyPair.publicKey, emptyMessage);
    const decrypted = await decryptEnvelope(keyPair.privateKey, envelope);

    expect(decrypted).toEqual(emptyMessage);
    expect(decrypted.length).toBe(0);
  });

  it("should produce different envelopes for the same message", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const message = new TextEncoder().encode("Same message");

    const envelope1 = await encryptEnvelope(keyPair.publicKey, message);
    const envelope2 = await encryptEnvelope(keyPair.publicKey, message);

    expect(envelope1).not.toBe(envelope2); // Should be different due to random AES keys

    const decrypted1 = await decryptEnvelope(keyPair.privateKey, envelope1);
    const decrypted2 = await decryptEnvelope(keyPair.privateKey, envelope2);

    expect(new TextDecoder().decode(decrypted1)).toBe("Same message");
    expect(new TextDecoder().decode(decrypted2)).toBe("Same message");
  });

  it("should fail with invalid envelope format", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");

    await expect(
      decryptEnvelope(keyPair.privateKey, "invalid-envelope")
    ).rejects.toThrow("Invalid encrypted message");

    await expect(
      decryptEnvelope(keyPair.privateKey, "only-one-part")
    ).rejects.toThrow("Invalid encrypted message");
  });

  it("should fail with wrong private key", async () => {
    const keyPair1 = await generateRSAKeyPair(2048, "bytes");
    const keyPair2 = await generateRSAKeyPair(2048, "bytes");
    const message = new TextEncoder().encode("Secret message");

    const envelope = await encryptEnvelope(keyPair1.publicKey, message);

    await expect(
      decryptEnvelope(keyPair2.privateKey, envelope)
    ).rejects.toThrow();
  });

  it("should work with different key sizes", async () => {
    const testKeySizes = [2048, 3072, 4096];

    for (const keySize of testKeySizes) {
      const keyPair = await generateRSAKeyPair(keySize, "bytes");
      const message = new TextEncoder().encode(`Test with ${keySize} bit key`);

      const envelope = await encryptEnvelope(keyPair.publicKey, message);
      const decrypted = await decryptEnvelope(keyPair.privateKey, envelope);
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(`Test with ${keySize} bit key`);
    }
  });

  it("should handle binary data correctly", async () => {
    const keyPair = await generateRSAKeyPair(2048, "bytes");
    const binaryData = new Uint8Array([0, 1, 2, 3, 255, 254, 253, 128, 127]);

    const envelope = await encryptEnvelope(keyPair.publicKey, binaryData);
    const decrypted = await decryptEnvelope(keyPair.privateKey, envelope);

    expect(decrypted).toEqual(binaryData);
  });
});
