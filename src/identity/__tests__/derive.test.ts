import { describe, it, expect } from "vitest";
import { fromUint8Array } from "js-base64";
import {
  deriveIdentityPqSeed,
  deriveIdentityPqKeyPair,
  derivePortalPqSeed,
  matchesOnchainIdentityKey,
} from "../derive";
import { encodeIdentityPublicKey } from "../codec";
import { deriveHKDFKey } from "../../kdf";
import {
  HKDF_INFO_IDENTITY_PQ,
  HKDF_INFO_PORTAL_PQ,
} from "../config";
import { generatePqKeyPair, pqEncrypt, pqDecrypt } from "../../pq";

// Shaped like the real inputs: ag2Hash = base64 of 32 bytes, ownerSecret =
// base64 of 64 bytes, portal address = 20-byte 0x hex.
const AG2 = fromUint8Array(Uint8Array.from({ length: 32 }, (_, i) => i * 7));
const SALT = Uint8Array.from({ length: 24 }, (_, i) => i * 3);
const OWNER_SECRET = fromUint8Array(
  Uint8Array.from({ length: 64 }, (_, i) => 255 - i)
);
const PORTAL_ADDRESS = "0xAbCdEf0123456789aBcDeF0123456789abcdef01";

const utf8 = (s: string) => new TextEncoder().encode(s);

describe("identity derivation", () => {
  it("is deterministic across calls (the whole design rests on this)", async () => {
    const a = deriveIdentityPqSeed(AG2, SALT);
    const b = deriveIdentityPqSeed(AG2, SALT);
    expect(a).toEqual(b);

    const kpA = await deriveIdentityPqKeyPair(AG2, SALT);
    const kpB = await deriveIdentityPqKeyPair(AG2, SALT);
    expect(kpA.publicKey).toEqual(kpB.publicKey);
    expect(kpA.privateKey).toEqual(kpB.privateKey);
  });

  it("separates domains: the identity and portal labels never collide", () => {
    // Input validation makes it impossible to feed the same raw material
    // through both public paths (they demand different shapes), so the
    // domain-separation proof runs at the kdf layer the paths share.
    const ikm = utf8(AG2);
    expect(
      deriveHKDFKey(ikm, SALT, utf8(HKDF_INFO_IDENTITY_PQ))
    ).not.toEqual(deriveHKDFKey(ikm, SALT, utf8(HKDF_INFO_PORTAL_PQ)));
  });

  it("different inputs give different keys", () => {
    const otherAg2 = fromUint8Array(
      Uint8Array.from({ length: 32 }, (_, i) => i * 7 + 1)
    );
    expect(deriveIdentityPqSeed(AG2, SALT)).not.toEqual(
      deriveIdentityPqSeed(otherAg2, SALT)
    );
    const otherSalt = Uint8Array.from(SALT);
    otherSalt[0] ^= 1;
    expect(deriveIdentityPqSeed(AG2, SALT)).not.toEqual(
      deriveIdentityPqSeed(AG2, otherSalt)
    );
  });

  it("derived keypair actually encrypts and decrypts", async () => {
    const kp = await deriveIdentityPqKeyPair(AG2, SALT);
    const msg = new TextEncoder().encode("envelope to a derived identity");
    const ct = await pqEncrypt(kp.publicKey, msg);
    expect(await pqDecrypt(kp.privateKey, ct)).toEqual(msg);
  });
});

describe("input validation (garbage must throw, never derive)", () => {
  it("deriveIdentityPqSeed rejects malformed ag2Hash", () => {
    expect(() => deriveIdentityPqSeed("", SALT)).toThrow();
    expect(() => deriveIdentityPqSeed("not valid base64 !!!", SALT)).toThrow();
    // valid base64, wrong decoded length (31 and 33 bytes)
    expect(() =>
      deriveIdentityPqSeed(fromUint8Array(new Uint8Array(31)), SALT)
    ).toThrow();
    expect(() =>
      deriveIdentityPqSeed(fromUint8Array(new Uint8Array(33)), SALT)
    ).toThrow();
    // right bytes, non-canonical encoding (stripped padding)
    expect(() => deriveIdentityPqSeed(AG2.replace(/=+$/, ""), SALT)).toThrow();
  });

  it("deriveIdentityPqSeed rejects an empty salt", () => {
    expect(() => deriveIdentityPqSeed(AG2, new Uint8Array(0))).toThrow();
  });

  it("derivePortalPqSeed rejects malformed ownerSecret", () => {
    expect(() => derivePortalPqSeed("", PORTAL_ADDRESS)).toThrow();
    expect(() =>
      derivePortalPqSeed("not valid base64 !!!", PORTAL_ADDRESS)
    ).toThrow();
    expect(() =>
      derivePortalPqSeed(fromUint8Array(new Uint8Array(32)), PORTAL_ADDRESS)
    ).toThrow();
    expect(() =>
      derivePortalPqSeed(OWNER_SECRET.replace(/=+$/, ""), PORTAL_ADDRESS)
    ).toThrow();
  });

  it("derivePortalPqSeed rejects malformed portal addresses", () => {
    expect(() => derivePortalPqSeed(OWNER_SECRET, "")).toThrow();
    expect(() =>
      derivePortalPqSeed(OWNER_SECRET, PORTAL_ADDRESS.slice(2))
    ).toThrow();
    expect(() =>
      derivePortalPqSeed(OWNER_SECRET, PORTAL_ADDRESS.slice(0, -1))
    ).toThrow();
    expect(() =>
      derivePortalPqSeed(OWNER_SECRET, PORTAL_ADDRESS.slice(0, -1) + "g")
    ).toThrow();
  });

  it("address casing does not change the derived key, different addresses do", () => {
    const checksummed = derivePortalPqSeed(OWNER_SECRET, PORTAL_ADDRESS);
    const lower = derivePortalPqSeed(
      OWNER_SECRET,
      PORTAL_ADDRESS.toLowerCase()
    );
    expect(checksummed).toEqual(lower);

    const otherAddress = "0x" + "1".repeat(40);
    expect(derivePortalPqSeed(OWNER_SECRET, otherAddress)).not.toEqual(
      checksummed
    );
  });
});

describe("matchesOnchainIdentityKey (the login drift guard)", () => {
  it("accepts the matching onchain blob", async () => {
    const kp = await deriveIdentityPqKeyPair(AG2, SALT);
    const onchain = encodeIdentityPublicKey(kp.publicKey);
    expect(matchesOnchainIdentityKey(kp.publicKey, onchain)).toBe(true);
  });

  it("rejects a different key — drift must never pass", async () => {
    const kp = await deriveIdentityPqKeyPair(AG2, SALT);
    const other = await generatePqKeyPair();
    const onchain = encodeIdentityPublicKey(other.publicKey);
    expect(matchesOnchainIdentityKey(kp.publicKey, onchain)).toBe(false);
  });

  it("returns false for legacy-format and garbage blobs (never throws)", async () => {
    const kp = await deriveIdentityPqKeyPair(AG2, SALT);
    const rsaLike = new Uint8Array([0x30, 0x82, 0x01, 0x22, 0x05]);
    expect(matchesOnchainIdentityKey(kp.publicKey, rsaLike)).toBe(false);
    expect(matchesOnchainIdentityKey(kp.publicKey, new Uint8Array(0))).toBe(false);
    expect(
      matchesOnchainIdentityKey(kp.publicKey, new Uint8Array([1, 2, 3]))
    ).toBe(false);
  });
});
