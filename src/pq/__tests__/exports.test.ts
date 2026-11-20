import { describe, it, expect } from "vitest";
import * as pq from "..";
import * as root from "../..";
import { getPublicKey as eciesGetPublicKey } from "../../ecies";

describe("PQ public export surface", () => {
  it("exposes the full spec surface via the pq barrel", () => {
    expect(typeof pq.generatePqKeyPair).toBe("function");
    expect(typeof pq.getPublicKey).toBe("function");
    expect(typeof pq.pqEncrypt).toBe("function");
    expect(typeof pq.pqDecrypt).toBe("function");
    expect(typeof pq.parsePqCipherString).toBe("function");
    expect(typeof pq.VERSION).toBe("string");
    expect(pq.INFO instanceof Uint8Array).toBe(true);
    expect(pq.SUITE).toEqual({
      kem: "X-Wing",
      kdf: "HKDF-SHA256",
      aead: "AES-256-GCM",
    });
  });

  it("round-trips through the barrel exports", async () => {
    const message = new TextEncoder().encode("barrel round-trip");
    const keyPair = await pq.generatePqKeyPair();

    const encrypted = await pq.pqEncrypt(keyPair.publicKey, message);
    const decrypted = await pq.pqDecrypt(keyPair.privateKey, encrypted);

    expect(new Uint8Array(decrypted)).toEqual(message);
  });

  it("re-exports the pq functions from the root barrel", () => {
    expect(root.generatePqKeyPair).toBe(pq.generatePqKeyPair);
    expect(root.pqEncrypt).toBe(pq.pqEncrypt);
    expect(root.pqDecrypt).toBe(pq.pqDecrypt);
    expect(root.parsePqCipherString).toBe(pq.parsePqCipherString);
  });

  it("mutating the exported INFO cannot break the key schedule", async () => {
    const message = new TextEncoder().encode("info mutation immunity");
    const keyPair = await pq.generatePqKeyPair();
    const before = await pq.pqEncrypt(keyPair.publicKey, message);

    pq.INFO[0] ^= 0xff;
    try {
      // Old and new ciphertexts must both stay decryptable: the exported INFO
      // is a defensive copy, not the bytes the key schedule uses.
      const after = await pq.pqEncrypt(keyPair.publicKey, message);
      expect(
        new Uint8Array(await pq.pqDecrypt(keyPair.privateKey, before))
      ).toEqual(message);
      expect(
        new Uint8Array(await pq.pqDecrypt(keyPair.privateKey, after))
      ).toEqual(message);
    } finally {
      pq.INFO[0] ^= 0xff;
    }
  });

  it("keeps root getPublicKey resolving to the ECIES export (collision policy)", () => {
    // The root barrel deliberately does NOT re-export pq's getPublicKey; the
    // ECIES one must keep winning so existing consumers see no change.
    expect(root.getPublicKey).toBe(eciesGetPublicKey);
    expect(root.getPublicKey).not.toBe(pq.getPublicKey);
  });
});
