import { describe, it, expect } from "vitest";
import {
  encodeIdentityPublicKey,
  decodeIdentityPublicKey,
} from "../codec";
import { IDENTITY_PQ_TAG, XWING_PUBLIC_KEY_LEN } from "../config";
import { generatePqKeyPair } from "../../pq";

const TAG_LEN = IDENTITY_PQ_TAG.length;

// A real-shaped RSA SPKI prefix: SEQUENCE, long-form length — how every
// legacy accountPublicKey blob begins.
const rsaLikeSpki = () => {
  const der = new Uint8Array(294);
  der[0] = 0x30;
  der[1] = 0x82;
  der[2] = 0x01;
  der[3] = 0x22;
  for (let i = 4; i < der.length; i++) der[i] = (i * 7) & 0xff;
  return der;
};

describe("identity public key codec", () => {
  it("round-trips a real X-Wing public key", async () => {
    const kp = await generatePqKeyPair();
    const blob = encodeIdentityPublicKey(kp.publicKey);
    expect(blob.length).toBe(TAG_LEN + XWING_PUBLIC_KEY_LEN);

    const decoded = decodeIdentityPublicKey(blob);
    expect(decoded.format).toBe("pq");
    if (decoded.format === "pq") {
      expect(decoded.publicKey).toEqual(kp.publicKey);
    }
  });

  it("rejects encoding a wrong-length public key (incl. off-by-one)", () => {
    expect(() =>
      encodeIdentityPublicKey(new Uint8Array(XWING_PUBLIC_KEY_LEN - 1))
    ).toThrow();
    expect(() =>
      encodeIdentityPublicKey(new Uint8Array(XWING_PUBLIC_KEY_LEN + 1))
    ).toThrow();
    expect(() => encodeIdentityPublicKey(new Uint8Array(0))).toThrow();
  });

  it("rejects truncated and oversized tagged blobs", async () => {
    const kp = await generatePqKeyPair();
    const blob = encodeIdentityPublicKey(kp.publicKey);
    expect(() => decodeIdentityPublicKey(blob.slice(0, blob.length - 1))).toThrow();
    const oversized = new Uint8Array(blob.length + 1);
    oversized.set(blob, 0);
    expect(() => decodeIdentityPublicKey(oversized)).toThrow();
    // Tag alone is not a key.
    expect(() => decodeIdentityPublicKey(blob.slice(0, TAG_LEN))).toThrow();
  });

  it("classifies a DER SPKI blob as the legacy rsa format", () => {
    const spki = rsaLikeSpki();
    const decoded = decodeIdentityPublicKey(spki);
    expect(decoded.format).toBe("rsa");
    if (decoded.format === "rsa") {
      expect(decoded.spki).toEqual(spki);
    }
  });

  it("throws on unknown formats — never guesses", () => {
    expect(() => decodeIdentityPublicKey(new Uint8Array(0))).toThrow();
    expect(() => decodeIdentityPublicKey(new Uint8Array([0x01, 0x02]))).toThrow();
    const almostTag = new TextEncoder().encode("FVPQID2");
    const blob = new Uint8Array(TAG_LEN + XWING_PUBLIC_KEY_LEN);
    blob.set(almostTag, 0);
    expect(() => decodeIdentityPublicKey(blob)).toThrow();
  });
});
