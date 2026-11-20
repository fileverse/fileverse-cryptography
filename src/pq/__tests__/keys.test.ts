import { describe, it, expect } from "vitest";
import { generatePqKeyPair, getPublicKey } from "../keys";
import { deriveHKDFKey } from "../../kdf";
import { toBytes } from "../../utils";

const PUBLIC_KEY_LEN = 1216; // X-Wing serialized public key
const PRIVATE_KEY_LEN = 32; // X-Wing seed (the private key)

describe("PQ Key Functions", () => {
  describe("generatePqKeyPair", () => {
    it("should generate a key pair with bytes encoding by default", async () => {
      const keyPair = await generatePqKeyPair();

      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      expect(keyPair.publicKey instanceof Uint8Array).toBe(true);
      expect(keyPair.privateKey instanceof Uint8Array).toBe(true);
      expect(keyPair.publicKey.length).toBe(PUBLIC_KEY_LEN);
      expect(keyPair.privateKey.length).toBe(PRIVATE_KEY_LEN);
    });

    it("should generate a key pair with base64 encoding when specified", async () => {
      const keyPair = await generatePqKeyPair(undefined, "base64");

      expect(typeof keyPair.publicKey).toBe("string");
      expect(typeof keyPair.privateKey).toBe("string");
      expect(toBytes(keyPair.publicKey).length).toBe(PUBLIC_KEY_LEN);
      expect(toBytes(keyPair.privateKey).length).toBe(PRIVATE_KEY_LEN);
    });

    it("should generate different key pairs on each call (random)", async () => {
      const keyPair1 = await generatePqKeyPair();
      const keyPair2 = await generatePqKeyPair();

      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    });

    it("should be deterministic for the same seed", async () => {
      const seed = new Uint8Array(32).fill(7);

      const keyPair1 = await generatePqKeyPair(seed);
      const keyPair2 = await generatePqKeyPair(seed);

      expect(keyPair1.publicKey).toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).toEqual(keyPair2.privateKey);
    });

    it("should produce different keys for different seeds", async () => {
      const keyPair1 = await generatePqKeyPair(new Uint8Array(32).fill(1));
      const keyPair2 = await generatePqKeyPair(new Uint8Array(32).fill(2));

      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    });

    it("should return a copy of the seed as the private key (equal, not aliased)", async () => {
      const seed = crypto.getRandomValues(new Uint8Array(32));
      const keyPair = await generatePqKeyPair(seed);

      expect(keyPair.privateKey).toEqual(seed);
      expect(keyPair.privateKey).not.toBe(seed);

      // Mutating the caller's seed must not corrupt the returned private key.
      const before = Uint8Array.from(keyPair.privateKey);
      seed.fill(0);
      expect(keyPair.privateKey).toEqual(before);
    });

    it("should accept a subarray view of a larger buffer as seed", async () => {
      const backing = crypto.getRandomValues(new Uint8Array(64));
      const view = backing.subarray(0, 32);

      const fromView = await generatePqKeyPair(view);
      const fromCopy = await generatePqKeyPair(Uint8Array.from(view));

      expect(fromView.publicKey).toEqual(fromCopy.publicKey);
      expect(fromView.privateKey).toEqual(fromCopy.privateKey);
    });

    it("should reject seeds that are not exactly 32 bytes", async () => {
      await expect(generatePqKeyPair(new Uint8Array(31))).rejects.toThrow(
        "Invalid seed length"
      );
      await expect(generatePqKeyPair(new Uint8Array(33))).rejects.toThrow(
        "Invalid seed length"
      );
      await expect(generatePqKeyPair(new Uint8Array(0))).rejects.toThrow(
        "Invalid seed length"
      );
      await expect(generatePqKeyPair(new Uint8Array(48))).rejects.toThrow(
        "Invalid seed length"
      );
    });
  });

  describe("getPublicKey", () => {
    it("should derive the same public key the keypair produced", async () => {
      const seed = new Uint8Array(32).fill(9);
      const keyPair = await generatePqKeyPair(seed);

      const derivedPublicKey = await getPublicKey(keyPair.privateKey);

      expect(derivedPublicKey).toEqual(keyPair.publicKey);
    });

    it("should be deterministic for the same private key", async () => {
      const { privateKey } = await generatePqKeyPair();

      const pub1 = await getPublicKey(privateKey);
      const pub2 = await getPublicKey(privateKey);

      expect(pub1).toEqual(pub2);
    });

    it("should return base64 when specified", async () => {
      const { privateKey } = await generatePqKeyPair();

      const publicKey = await getPublicKey(privateKey, "base64");

      expect(typeof publicKey).toBe("string");
      expect(toBytes(publicKey).length).toBe(PUBLIC_KEY_LEN);
    });

    it("should accept a subarray view of a larger buffer", async () => {
      const backing = crypto.getRandomValues(new Uint8Array(64));
      const view = backing.subarray(0, 32);

      const fromView = await getPublicKey(view);
      const fromCopy = await getPublicKey(Uint8Array.from(view));

      expect(fromView).toEqual(fromCopy);
    });

    it("should reject private keys that are not exactly 32 bytes", async () => {
      await expect(getPublicKey(new Uint8Array(0))).rejects.toThrow(
        "Invalid private key length"
      );
      await expect(getPublicKey(new Uint8Array(31))).rejects.toThrow(
        "Invalid private key length"
      );
      await expect(getPublicKey(new Uint8Array(64))).rejects.toThrow(
        "Invalid private key length"
      );
    });
  });

  describe("Domain-separated seed derivation (portalSeed pattern)", () => {
    // The consuming apps derive the PQ seed from an existing root seed via
    // HKDF with a domain-separating info string; the classical key uses a
    // different derivation. This pins that pattern at the library level.
    it("derives independent, deterministic keypairs from one root seed", async () => {
      const portalSeed = crypto.getRandomValues(new Uint8Array(32));
      const salt = new Uint8Array(0);

      const pqSeed = deriveHKDFKey(
        portalSeed,
        salt,
        new TextEncoder().encode("fileverse/pq-xwing/v1")
      );
      expect(pqSeed.length).toBe(32);

      const kp1 = await generatePqKeyPair(pqSeed);
      const kp2 = await generatePqKeyPair(
        deriveHKDFKey(
          portalSeed,
          salt,
          new TextEncoder().encode("fileverse/pq-xwing/v1")
        )
      );
      expect(kp1.publicKey).toEqual(kp2.publicKey);

      const otherDomain = await generatePqKeyPair(
        deriveHKDFKey(
          portalSeed,
          salt,
          new TextEncoder().encode("fileverse/other/v1")
        )
      );
      expect(otherDomain.publicKey).not.toEqual(kp1.publicKey);
      expect(otherDomain.privateKey).not.toEqual(kp1.privateKey);
    });
  });
});
