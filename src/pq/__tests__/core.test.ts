import { describe, it, expect } from "vitest";
import { pqEncrypt, pqDecrypt, parsePqCipherString } from "../core";
import { generatePqKeyPair } from "../keys";
import { cipherSuite, INFO_BYTES, VERSION, xwingKem } from "../config";
import { SEPARATOR } from "../../constants";
import { toBytes, bytesToBase64 } from "../../utils";
import { PqCipher } from "..";
import {
  eciesEncrypt,
  generateECKeyPair,
  parseEciesCipherString,
} from "../../ecies";

describe("PQ Core Functionality", () => {
  const testMessage = "Hello, post-quantum world!";
  const messageBytes = new TextEncoder().encode(testMessage);

  describe("pqEncrypt", () => {
    it('should encrypt and return a PqCipher object when format is "raw"', async () => {
      const { publicKey } = await generatePqKeyPair();

      const encrypted = await pqEncrypt(publicKey, messageBytes, "raw");

      expect(encrypted).toHaveProperty("version");
      expect(encrypted).toHaveProperty("enc");
      expect(encrypted).toHaveProperty("ciphertext");
      expect(encrypted.version).toBe(VERSION);
      expect(typeof encrypted.enc).toBe("string");
      expect(typeof encrypted.ciphertext).toBe("string");
    });

    it("should encrypt and return a concatenated string by default", async () => {
      const { publicKey } = await generatePqKeyPair();

      const encrypted = await pqEncrypt(publicKey, messageBytes);

      expect(typeof encrypted).toBe("string");
      expect(encrypted.split(SEPARATOR).length).toBe(3);
      expect(encrypted.startsWith(VERSION + SEPARATOR)).toBe(true);
    });

    it("should produce different ciphertexts for the same plaintext", async () => {
      const { publicKey } = await generatePqKeyPair();

      const encrypted1 = await pqEncrypt(publicKey, messageBytes);
      const encrypted2 = await pqEncrypt(publicKey, messageBytes);

      expect(encrypted1).not.toBe(encrypted2);
    });
  });

  describe("parsePqCipherString", () => {
    it("should parse a valid concatenated string into a PqCipher object", async () => {
      const { publicKey } = await generatePqKeyPair();
      const encryptedString = await pqEncrypt(publicKey, messageBytes);

      const parsed = parsePqCipherString(encryptedString);

      expect(parsed.version).toBe(VERSION);
      expect(typeof parsed.enc).toBe("string");
      expect(typeof parsed.ciphertext).toBe("string");
    });

    it("should throw on a string with the wrong number of parts", () => {
      expect(() => parsePqCipherString("not-a-valid-cipher")).toThrow(
        "Invalid encrypted data format"
      );
    });

    it("should throw on missing parts (empty segment)", () => {
      const bad = `${VERSION}${SEPARATOR}${SEPARATOR}ciphertext`;
      expect(() => parsePqCipherString(bad)).toThrow(
        "Missing required parts in encrypted data"
      );
    });

    it("should throw on an unsupported version tag", () => {
      const bad = `BADVER${SEPARATOR}enc${SEPARATOR}ciphertext`;
      expect(() => parsePqCipherString(bad)).toThrow(
        "Unsupported cipher version"
      );
    });

    it("should reject non-canonical base64 (stripped-character malleability)", async () => {
      const { publicKey } = await generatePqKeyPair();
      const valid = await pqEncrypt(publicKey, messageBytes);
      const [version, enc, ciphertext] = valid.split(SEPARATOR);

      // js-base64 would silently strip whitespace/garbage — we must not.
      // Inject into the ciphertext part (no fixed-length pre-check there).
      const injected = `${version}${SEPARATOR}${enc}${SEPARATOR}${ciphertext.slice(0, 8)} \n${ciphertext.slice(8)}`;
      expect(() => parsePqCipherString(injected)).toThrow(
        "Invalid encrypted data encoding"
      );

      // In-place URL-safe substitution keeps the length but changes the
      // alphabet — same decoded bytes, different wire string. (1120 random-ish
      // bytes contain a '+' or '/' with overwhelming probability; the
      // precondition assertion fails loudly in the astronomical case.)
      const urlSafeEnc = enc.replace(/\+/g, "-").replace(/\//g, "_");
      expect(urlSafeEnc).not.toBe(enc);
      expect(() =>
        parsePqCipherString(
          `${version}${SEPARATOR}${urlSafeEnc}${SEPARATOR}${ciphertext}`
        )
      ).toThrow("Invalid encrypted data encoding");

      // Stripping padding changes the string length, so it is caught by the
      // O(1) length pre-check before any decoding.
      const unpaddedEnc = enc.replace(/=/g, "");
      expect(unpaddedEnc).not.toBe(enc);
      expect(() =>
        parsePqCipherString(
          `${version}${SEPARATOR}${unpaddedEnc}${SEPARATOR}${ciphertext}`
        )
      ).toThrow("Invalid encapsulated key length");
    });

    it("should reject a wrong-length encapsulated key (incl. off-by-one)", async () => {
      const { publicKey } = await generatePqKeyPair();
      const valid = await pqEncrypt(publicKey, messageBytes, "raw");

      for (const badLen of [100, 1119, 1121]) {
        const wire = `${valid.version}${SEPARATOR}${bytesToBase64(new Uint8Array(badLen))}${SEPARATOR}${valid.ciphertext}`;
        expect(() => parsePqCipherString(wire)).toThrow(
          "Invalid encapsulated key length"
        );
      }
    });

    it("should reject a ciphertext shorter than the AEAD tag (incl. boundary)", async () => {
      const { publicKey } = await generatePqKeyPair();
      const valid = await pqEncrypt(publicKey, messageBytes, "raw");

      for (const badLen of [8, 15]) {
        const wire = `${valid.version}${SEPARATOR}${valid.enc}${SEPARATOR}${bytesToBase64(new Uint8Array(badLen))}`;
        expect(() => parsePqCipherString(wire)).toThrow(
          "Invalid ciphertext length"
        );
      }
    });
  });

  describe("pqDecrypt", () => {
    it("should correctly decrypt from a PqCipher object", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();

      const encrypted = await pqEncrypt(publicKey, messageBytes, "raw");
      const decrypted = await pqDecrypt(privateKey, encrypted);

      expect(new TextDecoder().decode(decrypted)).toBe(testMessage);
    });

    it("should correctly decrypt from a concatenated string", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();

      const encrypted = await pqEncrypt(publicKey, messageBytes);
      const decrypted = await pqDecrypt(privateKey, encrypted);

      expect(new TextDecoder().decode(decrypted)).toBe(testMessage);
    });

    it("should decrypt with a key re-derived from the same seed", async () => {
      const seed = crypto.getRandomValues(new Uint8Array(32));
      const { publicKey } = await generatePqKeyPair(seed);

      const encrypted = await pqEncrypt(publicKey, messageBytes);
      // Decrypt using the bare seed (the recipient re-derives the keypair).
      const decrypted = await pqDecrypt(seed, encrypted);

      expect(new TextDecoder().decode(decrypted)).toBe(testMessage);
    });

    it("should throw when decrypting with the wrong private key", async () => {
      const kp1 = await generatePqKeyPair();
      const kp2 = await generatePqKeyPair();

      const encrypted = await pqEncrypt(kp1.publicKey, messageBytes);

      await expect(pqDecrypt(kp2.privateKey, encrypted)).rejects.toThrow();
    });

    it("should throw on a tampered ciphertext (AEAD tag failure)", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();
      const encrypted = await pqEncrypt(publicKey, messageBytes, "raw");

      const ctBytes = toBytes(encrypted.ciphertext);
      ctBytes[ctBytes.length - 1] ^= 0xff;
      const tampered: PqCipher = {
        ...encrypted,
        ciphertext: bytesToBase64(ctBytes),
      };

      await expect(pqDecrypt(privateKey, tampered)).rejects.toThrow();
    });

    it("should throw on a tampered encapsulated key", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();
      const encrypted = await pqEncrypt(publicKey, messageBytes, "raw");

      const encBytes = toBytes(encrypted.enc);
      encBytes[0] ^= 0xff;
      const tampered: PqCipher = { ...encrypted, enc: bytesToBase64(encBytes) };

      await expect(pqDecrypt(privateKey, tampered)).rejects.toThrow();
    });

    it("should throw on an unsupported version", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();
      const encrypted = await pqEncrypt(publicKey, messageBytes, "raw");

      const tampered: PqCipher = { ...encrypted, version: "BADVER" };

      await expect(pqDecrypt(privateKey, tampered)).rejects.toThrow(
        "Unsupported cipher version"
      );
    });

    it("should reject a private key that is not exactly 32 bytes", async () => {
      const { publicKey } = await generatePqKeyPair();
      const encrypted = await pqEncrypt(publicKey, messageBytes);

      for (const badLen of [0, 31, 33, 64]) {
        await expect(
          pqDecrypt(new Uint8Array(badLen), encrypted)
        ).rejects.toThrow("Invalid private key length");
      }
    });

    it("should bind the version tag as AEAD associated data", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();
      const recipientPublicKey = await xwingKem.deserializePublicKey(publicKey);

      // Seal with the module's INFO but WITHOUT its AAD, wrap in an
      // otherwise-valid wire string: pqDecrypt must reject at the AEAD tag.
      const noAad = await cipherSuite.seal(
        { recipientPublicKey, info: INFO_BYTES },
        messageBytes
      );
      const noAadWire = `${VERSION}${SEPARATOR}${bytesToBase64(new Uint8Array(noAad.enc))}${SEPARATOR}${bytesToBase64(new Uint8Array(noAad.ct))}`;
      await expect(pqDecrypt(privateKey, noAadWire)).rejects.toThrow();

      // Same with a mismatched AAD value.
      const wrongAad = await cipherSuite.seal(
        { recipientPublicKey, info: INFO_BYTES },
        messageBytes,
        new TextEncoder().encode("FVPQ2")
      );
      const wrongAadWire = `${VERSION}${SEPARATOR}${bytesToBase64(new Uint8Array(wrongAad.enc))}${SEPARATOR}${bytesToBase64(new Uint8Array(wrongAad.ct))}`;
      await expect(pqDecrypt(privateKey, wrongAadWire)).rejects.toThrow();

      // Control: sealing with the module's own AAD is accepted.
      const rightAad = await cipherSuite.seal(
        { recipientPublicKey, info: INFO_BYTES },
        messageBytes,
        new TextEncoder().encode(VERSION)
      );
      const rightAadWire = `${VERSION}${SEPARATOR}${bytesToBase64(new Uint8Array(rightAad.enc))}${SEPARATOR}${bytesToBase64(new Uint8Array(rightAad.ct))}`;
      const decrypted = await pqDecrypt(privateKey, rightAadWire);
      expect(new TextDecoder().decode(decrypted)).toBe(testMessage);
    });

    it("should validate object-form ciphers with missing or non-string fields", async () => {
      const { privateKey } = await generatePqKeyPair();

      await expect(
        pqDecrypt(privateKey, { version: "FVPQ1" } as unknown as PqCipher)
      ).rejects.toThrow("Missing required parts in encrypted data");

      await expect(
        pqDecrypt(privateKey, {
          version: "FVPQ1",
          enc: 12345,
          ciphertext: "AAAA",
        } as unknown as PqCipher)
      ).rejects.toThrow("Missing required parts in encrypted data");

      // Wrong-length enc hits the O(1) length pre-check before any decoding.
      await expect(
        pqDecrypt(privateKey, {
          version: "FVPQ1",
          enc: "!!!!",
          ciphertext: "AAAA",
        } as unknown as PqCipher)
      ).rejects.toThrow("Invalid encapsulated key length");

      // Correct-length but non-canonical enc reaches the encoding check.
      const { publicKey } = await generatePqKeyPair();
      const valid = await pqEncrypt(publicKey, messageBytes, "raw");
      const nonCanonicalEnc = valid.enc.replace(/\+/g, "-").replace(/\//g, "_");
      expect(nonCanonicalEnc).not.toBe(valid.enc);
      await expect(
        pqDecrypt(privateKey, { ...valid, enc: nonCanonicalEnc })
      ).rejects.toThrow("Invalid encrypted data encoding");
    });
  });

  describe("Encryption/Decryption Cycle", () => {
    it("should round-trip various message types", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();

      const testCases = [
        { name: "Empty", data: new Uint8Array(0) },
        { name: "Short text", data: new TextEncoder().encode("Hi!") },
        { name: "Binary", data: new Uint8Array([1, 2, 3, 255, 0]) },
        { name: "Unicode", data: new TextEncoder().encode("Hello 🌍 世界") },
      ];

      for (const { data } of testCases) {
        const encryptedRaw = await pqEncrypt(publicKey, data, "raw");
        const decryptedRaw = await pqDecrypt(privateKey, encryptedRaw);
        expect(new Uint8Array(decryptedRaw)).toEqual(data);

        const encryptedB64 = await pqEncrypt(publicKey, data, "base64");
        const decryptedB64 = await pqDecrypt(privateKey, encryptedB64);
        expect(new Uint8Array(decryptedB64)).toEqual(data);
      }
    });

    it("should maintain integrity across all byte values", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();

      const allBytes = new Uint8Array(256);
      for (let i = 0; i < 256; i++) allBytes[i] = i;

      const encrypted = await pqEncrypt(publicKey, allBytes);
      const decrypted = await pqDecrypt(privateKey, encrypted);

      expect(decrypted).toEqual(allBytes);
    });

    it("should handle large messages", async () => {
      const { publicKey, privateKey } = await generatePqKeyPair();

      const largeMessage = new Uint8Array(1024 * 256);
      for (let i = 0; i < largeMessage.length; i++) largeMessage[i] = i % 256;

      const encrypted = await pqEncrypt(publicKey, largeMessage);
      const decrypted = await pqDecrypt(privateKey, encrypted);

      expect(decrypted).toEqual(largeMessage);
    });
  });

  describe("Backwards-compatibility / cross-version safety", () => {
    it("PQ strings and legacy ECIES strings are mutually unparseable", async () => {
      const pqKeyPair = await generatePqKeyPair();
      const ecKeyPair = generateECKeyPair();

      const pqString = await pqEncrypt(pqKeyPair.publicKey, messageBytes);
      const eciesString = eciesEncrypt(ecKeyPair.publicKey, messageBytes);

      // The legacy ECIES parser (4 parts) rejects a PQ string (3 parts).
      expect(() => parseEciesCipherString(pqString)).toThrow();
      // The PQ parser (3 parts) rejects a legacy ECIES string (4 parts).
      expect(() => parsePqCipherString(eciesString)).toThrow();
    });

    it("the version prefix distinguishes PQ from legacy ECIES on the wire", async () => {
      const pqKeyPair = await generatePqKeyPair();
      const ecKeyPair = generateECKeyPair();

      const pqString = await pqEncrypt(pqKeyPair.publicKey, messageBytes);
      const eciesString = eciesEncrypt(ecKeyPair.publicKey, messageBytes);

      // PQ blobs are self-describing; legacy blobs start with "A" (base64 of a
      // compressed secp256k1 point) and never with the PQ tag.
      expect(pqString.startsWith(VERSION + SEPARATOR)).toBe(true);
      expect(eciesString.startsWith(VERSION + SEPARATOR)).toBe(false);
    });
  });
});
