import { describe, it, expect } from "vitest";
import {
  rsaEncrypt,
  rsaDecrypt,
  rsaEncryptEnvelope,
  rsaDecryptEnvelope,
} from "../core";
import { generateRSAKeyPair } from "../keys";
import { toBytes } from "../../utils/encoding";
import { SEPERATOR } from "../../constants";

describe("RSA Core Functionality", () => {
  // Use smaller key size for faster tests
  const KEY_SIZE = 1024;

  describe("rsaEncrypt and rsaDecrypt", () => {
    it("should encrypt and decrypt a message correctly", async () => {
      const keyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const message = new TextEncoder().encode("Hello, RSA encryption!");

      const encrypted = await rsaEncrypt(keyPair.publicKey, message);
      expect(typeof encrypted).toBe("string");

      const decrypted = await rsaDecrypt(
        keyPair.privateKey,
        toBytes(encrypted)
      );
      expect(decrypted instanceof Uint8Array).toBe(true);

      const decodedMessage = new TextDecoder().decode(decrypted);
      expect(decodedMessage).toBe("Hello, RSA encryption!");
    });

    it("should return bytes output when specified", async () => {
      const keyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const message = new TextEncoder().encode("Test bytes output");

      const encrypted = await rsaEncrypt(keyPair.publicKey, message, "bytes");
      expect(encrypted instanceof Uint8Array).toBe(true);

      const decrypted = await rsaDecrypt(keyPair.privateKey, encrypted);

      const decodedMessage = new TextDecoder().decode(decrypted);
      expect(decodedMessage).toBe("Test bytes output");
    });

    it("should encrypt the same message differently each time (due to random nonce)", async () => {
      const keyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const message = new TextEncoder().encode("Same message");

      const encrypted1 = await rsaEncrypt(keyPair.publicKey, message);
      const encrypted2 = await rsaEncrypt(keyPair.publicKey, message);

      expect(encrypted1).not.toBe(encrypted2);

      // But both should decrypt to the same original message
      const decrypted1 = await rsaDecrypt(
        keyPair.privateKey,
        toBytes(encrypted1)
      );
      const decrypted2 = await rsaDecrypt(
        keyPair.privateKey,
        toBytes(encrypted2)
      );

      const decodedMessage1 = new TextDecoder().decode(decrypted1);
      const decodedMessage2 = new TextDecoder().decode(decrypted2);

      expect(decodedMessage1).toBe("Same message");
      expect(decodedMessage2).toBe("Same message");
    });

    it("should handle empty messages", async () => {
      const keyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const emptyMessage = new Uint8Array(0);

      const encrypted = await rsaEncrypt(keyPair.publicKey, emptyMessage);
      const decrypted = await rsaDecrypt(
        keyPair.privateKey,
        toBytes(encrypted)
      );

      expect(decrypted.byteLength).toBe(0);
    });

    it("should fail when decrypting with the wrong key", async () => {
      const keyPair1 = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const keyPair2 = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const message = new TextEncoder().encode("Secret message");

      const encrypted = await rsaEncrypt(keyPair1.publicKey, message);

      await expect(
        rsaDecrypt(keyPair2.privateKey, toBytes(encrypted))
      ).rejects.toThrow();
    });
  });

  describe("rsaEncryptEnvelope and rsaDecryptEnvelope", () => {
    it("should encrypt and decrypt a message correctly using envelope encryption", async () => {
      const keyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const message = new TextEncoder().encode("Envelope encryption test");

      const envelope = await rsaEncryptEnvelope(keyPair.publicKey, message);
      expect(typeof envelope).toBe("string");
      expect(envelope).toContain(SEPERATOR);

      const decrypted = await rsaDecryptEnvelope(keyPair.privateKey, envelope);
      expect(decrypted instanceof Uint8Array).toBe(true);

      const decodedMessage = new TextDecoder().decode(decrypted);
      expect(decodedMessage).toBe("Envelope encryption test");
    });

    it("should handle large messages with envelope encryption", async () => {
      const keyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");

      // Create a message larger than RSA can handle directly
      const largeMessage = new Uint8Array(1024 * 5); // 5KB message
      for (let i = 0; i < largeMessage.length; i++) {
        largeMessage[i] = i % 256;
      }

      const envelope = await rsaEncryptEnvelope(
        keyPair.publicKey,
        largeMessage
      );
      const decrypted = await rsaDecryptEnvelope(keyPair.privateKey, envelope);

      expect(decrypted.byteLength).toBe(largeMessage.byteLength);

      // Check a few random positions to ensure content matches
      for (let i = 0; i < 10; i++) {
        const pos = Math.floor(Math.random() * largeMessage.length);
        expect(decrypted[pos]).toBe(largeMessage[pos]);
      }
    });

    it("should throw an error for invalid envelope format", async () => {
      const keyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");

      // Missing separator
      const invalidEnvelope = "invalidEnvelopeString";

      await expect(
        rsaDecryptEnvelope(keyPair.privateKey, invalidEnvelope)
      ).rejects.toThrow("Invalid encrypted message");
    });

    it("should fail when decrypting with the wrong key", async () => {
      const keyPair1 = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const keyPair2 = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const message = new TextEncoder().encode("Secret envelope message");

      const envelope = await rsaEncryptEnvelope(keyPair1.publicKey, message);

      await expect(
        rsaDecryptEnvelope(keyPair2.privateKey, envelope)
      ).rejects.toThrow();
    });
  });

  describe("Practical Use Cases", () => {
    it("should successfully exchange messages between parties", async () => {
      // Generate keys for Alice and Bob
      const aliceKeyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");
      const bobKeyPair = await generateRSAKeyPair(KEY_SIZE, "bytes");

      // Alice encrypts a message for Bob using Bob's public key
      const aliceMessage = new TextEncoder().encode("Hi Bob, this is Alice!");
      const encryptedForBob = await rsaEncryptEnvelope(
        bobKeyPair.publicKey,
        aliceMessage
      );

      // Bob decrypts Alice's message using his private key
      const decryptedByBob = await rsaDecryptEnvelope(
        bobKeyPair.privateKey,
        encryptedForBob
      );
      const bobReceived = new TextDecoder().decode(decryptedByBob);
      expect(bobReceived).toBe("Hi Bob, this is Alice!");

      // Bob replies to Alice using Alice's public key
      const bobMessage = new TextEncoder().encode(
        "Hello Alice, got your message!"
      );
      const encryptedForAlice = await rsaEncryptEnvelope(
        aliceKeyPair.publicKey,
        bobMessage
      );

      // Alice decrypts Bob's message using her private key
      const decryptedByAlice = await rsaDecryptEnvelope(
        aliceKeyPair.privateKey,
        encryptedForAlice
      );
      const aliceReceived = new TextDecoder().decode(decryptedByAlice);
      expect(aliceReceived).toBe("Hello Alice, got your message!");
    });
  });
});
