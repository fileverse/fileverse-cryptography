import { describe, it, expect } from "vitest";
import { eciesEncrypt, eciesDecrypt, parseEciesCipherString } from "../core";
import { generateECKeyPair } from "../keys";
import { SEPERATOR } from "../../constants";
import { base64ToBytes, bytesToBase64 } from "../../utils";
import { EciesCipher } from "..";

describe("ECIES Core Functionality", () => {
  const testMessage = "Hello, world!";
  const messageBytes = new TextEncoder().encode(testMessage);

  describe("eciesEncrypt", () => {
    it('should encrypt a message and return an EciesCipher object when format is "raw"', () => {
      const keyPair = generateECKeyPair();
      const publicKey = keyPair.publicKey;

      const encrypted = eciesEncrypt(publicKey, messageBytes, "raw");

      expect(encrypted).toHaveProperty("ephemeralPublicKey");
      expect(encrypted).toHaveProperty("nonce");
      expect(encrypted).toHaveProperty("ciphertext");
      expect(encrypted).toHaveProperty("mac");

      expect(typeof encrypted.ephemeralPublicKey).toBe("string");
      expect(typeof encrypted.nonce).toBe("string");
      expect(typeof encrypted.ciphertext).toBe("string");
      expect(typeof encrypted.mac).toBe("string");
    });

    it("should encrypt a message and return a concatenated string by default", () => {
      const keyPair = generateECKeyPair();
      const publicKey = keyPair.publicKey;

      const encrypted = eciesEncrypt(publicKey, messageBytes);

      expect(typeof encrypted).toBe("string");

      expect(encrypted.split(SEPERATOR).length).toBe(4);
    });

    it('should encrypt a message and return a concatenated string when format is "base64"', () => {
      const keyPair = generateECKeyPair();
      const publicKey = keyPair.publicKey;

      const encrypted = eciesEncrypt(publicKey, messageBytes, "base64");

      expect(typeof encrypted).toBe("string");

      expect(encrypted.split(SEPERATOR).length).toBe(4);
    });

    it("should produce different ciphertexts for the same plaintext", () => {
      const keyPair = generateECKeyPair();
      const publicKey = keyPair.publicKey;

      const encrypted1 = eciesEncrypt(publicKey, messageBytes);
      const encrypted2 = eciesEncrypt(publicKey, messageBytes);

      expect(encrypted1).not.toBe(encrypted2);
    });
  });

  describe("parseEciesCipherString", () => {
    it("should parse a valid concatenated string into an EciesCipher object", () => {
      const keyPair = generateECKeyPair();
      const publicKey = keyPair.publicKey;

      const encryptedString = eciesEncrypt(publicKey, messageBytes);
      const parsedCipher = parseEciesCipherString(encryptedString);

      expect(typeof parsedCipher.ephemeralPublicKey).toBe("string");
      expect(typeof parsedCipher.nonce).toBe("string");
      expect(typeof parsedCipher.ciphertext).toBe("string");
      expect(typeof parsedCipher.mac).toBe("string");
    });

    it("should throw an error when parsing an invalid concatenated string (wrong format)", () => {
      const invalidString = "not-a-valid-encrypted-string";

      expect(() => parseEciesCipherString(invalidString)).toThrow();
    });

    it("should throw an error when parsing an invalid concatenated string (missing parts)", () => {
      const missingParts = `part1${SEPERATOR}part2`;

      expect(() => parseEciesCipherString(missingParts)).toThrow();
    });

    it("should throw an error when parsing an invalid concatenated string (empty parts)", () => {
      const emptyParts = `part1${SEPERATOR}${SEPERATOR}part3${SEPERATOR}part4`;

      expect(() => parseEciesCipherString(emptyParts)).toThrow();
    });
  });

  describe("eciesDecrypt", () => {
    it("should correctly decrypt a message from an EciesCipher object", () => {
      const keyPair = generateECKeyPair();
      const publicKey = keyPair.publicKey;
      const privateKey = keyPair.privateKey;

      const encrypted = eciesEncrypt(publicKey, messageBytes, "raw");
      const decrypted = eciesDecrypt(privateKey, encrypted);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(testMessage);
    });

    it("should correctly decrypt a message from a concatenated string", () => {
      const keyPair = generateECKeyPair();
      const publicKey = keyPair.publicKey;
      const privateKey = keyPair.privateKey;

      const encryptedString = eciesEncrypt(publicKey, messageBytes);
      const decrypted = eciesDecrypt(privateKey, encryptedString);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(testMessage);
    });

    it("should throw an error when decrypting with the wrong private key", () => {
      const keyPair1 = generateECKeyPair();
      const keyPair2 = generateECKeyPair();

      const encrypted = eciesEncrypt(keyPair1.publicKey, messageBytes);

      expect(() => eciesDecrypt(keyPair2.privateKey, encrypted)).toThrow();
    });

    it("should handle empty messages correctly", () => {
      const keyPair = generateECKeyPair();
      const emptyMessage = new Uint8Array(0);

      const publicKey = keyPair.publicKey as string;
      const privateKey = keyPair.privateKey as string;

      const encrypted = eciesEncrypt(publicKey, emptyMessage, "raw");

      const decrypted = eciesDecrypt(privateKey, encrypted);

      expect(decrypted).toBeDefined();
      expect(decrypted instanceof Uint8Array).toBe(true);
      expect(decrypted.byteLength).toBe(0);
    });

    it("should handle large messages correctly", () => {
      const keyPair = generateECKeyPair();
      const largeMessage = new Uint8Array(1024 * 1024);
      for (let i = 0; i < largeMessage.length; i++) {
        largeMessage[i] = Math.floor(Math.random() * 256);
      }

      const encrypted = eciesEncrypt(keyPair.publicKey, largeMessage);
      const decrypted = eciesDecrypt(keyPair.privateKey, encrypted);

      expect(decrypted.byteLength).toBe(largeMessage.byteLength);
      for (let i = 0; i < 10; i++) {
        const pos = Math.floor(Math.random() * largeMessage.length);
        expect(decrypted[pos]).toBe(largeMessage[pos]);
      }
    });
  });

  describe("Encryption/Decryption Cycle", () => {
    it("should correctly round-trip various message types", () => {
      const testCases = [
        { name: "Short text", data: new TextEncoder().encode("Hello!") },
        { name: "Binary data", data: new Uint8Array([1, 2, 3, 4, 5]) },
      ];

      const keyPair = generateECKeyPair();
      const publicKey = keyPair.publicKey as string;
      const privateKey = keyPair.privateKey as string;

      const emptyData = new Uint8Array(0);
      const encryptedEmpty = eciesEncrypt(publicKey, emptyData, "raw");
      const decryptedEmpty = eciesDecrypt(privateKey, encryptedEmpty);
      expect(decryptedEmpty.byteLength).toBe(0);

      for (const { name, data } of testCases) {
        const encryptedRaw = eciesEncrypt(publicKey, data, "raw");
        const decryptedRaw = eciesDecrypt(privateKey, encryptedRaw);
        expect(new Uint8Array(decryptedRaw)).toEqual(data);

        const encryptedBase64 = eciesEncrypt(publicKey, data, "base64");
        const decryptedBase64 = eciesDecrypt(privateKey, encryptedBase64);
        expect(new Uint8Array(decryptedBase64)).toEqual(data);
      }
    });

    it("should maintain data integrity across encryption/decryption", () => {
      const keyPair = generateECKeyPair();

      const allBytes = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i;
      }

      const encrypted = eciesEncrypt(keyPair.publicKey, allBytes);
      const decrypted = eciesDecrypt(keyPair.privateKey, encrypted);

      for (let i = 0; i < 256; i++) {
        expect(decrypted[i]).toBe(i);
      }
    });
  });

  describe("Edge Cases and Error Handling", () => {
    it("should throw an error when encrypting with an invalid public key", () => {
      const invalidPublicKey = "not-a-valid-key";

      expect(() => eciesEncrypt(invalidPublicKey, messageBytes)).toThrow();
    });

    it("should throw an error when decrypting with an invalid private key", () => {
      const keyPair = generateECKeyPair();
      const encrypted = eciesEncrypt(keyPair.publicKey, messageBytes);
      const invalidPrivateKey = "not-a-valid-key";

      expect(() => eciesDecrypt(invalidPrivateKey, encrypted)).toThrow();
    });

    it("should handle corrupted ciphertext gracefully", () => {
      const keyPair = generateECKeyPair();
      const encrypted = eciesEncrypt(keyPair.publicKey, messageBytes, "raw");

      const corruptedCiphertext: EciesCipher = {
        ...encrypted,
        ciphertext: "corrupted-data",
      };

      expect(() =>
        eciesDecrypt(keyPair.privateKey, corruptedCiphertext)
      ).toThrow();
    });

    it("should handle corrupted MAC gracefully", () => {
      const keyPair = generateECKeyPair();
      const encrypted = eciesEncrypt(keyPair.publicKey, messageBytes, "raw");

      const corruptedMac: EciesCipher = {
        ...encrypted,
        mac: "corrupted-mac",
      };

      expect(() => eciesDecrypt(keyPair.privateKey, corruptedMac)).toThrow();
    });
  });
});
