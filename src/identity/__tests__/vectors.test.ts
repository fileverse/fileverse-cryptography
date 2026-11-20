import { describe, it, expect } from "vitest";
import { toUint8Array, fromUint8Array } from "js-base64";
import { deriveHKDFKey } from "../../kdf";
import {
  deriveIdentityPqSeed,
  deriveIdentityPqKeyPair,
  derivePortalPqSeed,
} from "../derive";
import {
  IDENTITY_PQ_TAG,
  HKDF_INFO_IDENTITY_PQ,
  HKDF_INFO_PORTAL_PQ,
  XWING_PUBLIC_KEY_LEN,
  SEED_LEN,
} from "../config";

const hexToBytes = (hex: string) =>
  Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const bytesToHex = (bytes: Uint8Array) =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

// ─── Cross-implementation vectors ────────────────────────────────────────────
// The expected outputs below were CAPTURED from the consuming app's real
// derivation implementation (futoin-hkdf, utils/identity-utils/
// key-derivation-utils.ts) on 2026-08-25 — they were NOT computed by this
// library. These tests prove this library's HKDF is byte-identical to what
// production already runs, including the load-bearing quirk that the IKM is
// the UTF-8 bytes of the base64 ag2Hash STRING (not the decoded bytes).
// Never regenerate these values from this library's own output.
//
// Reproduce every pinned value with `npm run capture:vectors` — the script
// (scripts/capture-vectors.mjs) recomputes them with futoin-hkdf (the app's
// HKDF, exact call shape quoted from app source) and Node's crypto.hkdfSync,
// neither of which this library uses, and fails on any mismatch.

const VECTOR_AG2_HASH = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const VECTOR_SALT = hexToBytes(
  "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
);
// futoin-hkdf output for info "MASTER_KEY" — the app's existing key family.
const EXPECTED_MASTER_KEY_HEX =
  "58107ede9d587b268cb585acfc13cc6f522cd2f36cdfb430ea5ba987ce2da4c3";
// futoin-hkdf output for info "PQ_IDENTITY_KEY" — the new sibling.
const EXPECTED_IDENTITY_SEED_HEX =
  "9250a62c80c9dbd8266ace57edbfcee59e7e0a3bfa5bfd92a5faabd23ca6e467";

// Chained vector: EXPECTED_IDENTITY_SEED → X-Wing keypair (via the 0.0.23
// module's seeded, KAT-tested keygen) → this exact public key.
const EXPECTED_IDENTITY_PUBLIC_KEY_B64 =
  "0+QUujUAeKajG3K7gelxyNopdCwY9LG8eVNTwJvGxPoImLgWTuTNEXPDaXQypmit2pxJnYUT0nJMytO0kjcXsgxJ0el7YyXPxaJrfDI7g3AG7+AF1PZrI5GN6ttsMtAxspoXhrV7EphYYuU87zlGqNXDu7Uyq0QkFRNqfXUDpXw9kkp02agnFBmxhfoiZJE4+9ILIVBUZJli1Vh8cLmi0zB4VtElqrWYxAiKFfeIB4VpLZaJkPkLQ+suk8IHhYVYBJkMapODZXmV2Jk4slZd4TaRTByRBBy+0dHO4ABvkegOyloiGhMNatwQt8GvhmtbqFdh41Sp/1xV3XuRRAq8EUIcJyaNgknPhBZZMCWe/fRJhfVnk9eA4hyuSNbHOox+FoxzFgcomPihVpJm9dkiOAI2iyN6rmZhDdqGLfmPmiyikmmm/NAMOMjDS3s0YsS/Z2VRiPutmiaOoLuUl6pzC4fKsvRuidV0lDZ4u4ALoOcRwKBo2KkCG1LOqwmvxOUUrIuvUUJt3Ld0caTIsxAOMzgzYwcCUinDUYJ2iyuc/aBwiXpAaitZDfsqm7nEo4YXOGNtezpiHANIH9S+mMLJ14rJH4Bsq+UM9ZHPjJgVc+aQ8QqEqFclvSwB0PCBIdwTCcjBFguEUOInuCZV+BB+2LBUksVbdxAEgAQRpYela8TErNaPXbN31IwDOHU8z+UkEHBFcSC4EoyiklJ/98hd5OwM4HWOrgQKm9JeU1IhOqWrTmiWq+tK6RmkdJUxVuE8wBBB6UC/gqMv5RMMz6Utq2UntDwieiIWxLAIZ1eiFGGUGreQhWwO6uduw6ejtpFFfrir8aeq9GyD+TBtedgLWBw2zlIOO2EI7VBFE0aqIFBEwxmLKvQOpbmQN4nL7phXuJHKQbkc7SXEnYibhaArsnybKxrMBClOMjYMhcRdPwrL2OYFfKxRR2JrqnJCUbyqmBM17ewGG2A2L/qdXQYvSRllMkmE7JbA+2A6AuV+XMajxNDBMlEGjPfDRhgFWjkZ/4RfAqZHZqXJBKNEcPRCRkchtCudoZiKXGltHkFxajtUS2io2tOzIHNXU1HFSuSOKbAwB8yCYloXYwJqs7tR54zHZipP4+ufokggFEQixoqpZ4Rt0QtAZJhWmtvFnvqwUVR7NdVkT1bK9+kO5DifklCUU1TAe+dggjx72oyny8EHnPsCjUAm8Gg3rPkYGBhzxlK6YBE9C7qF2fcj/IDK/8QSbboj57MNX1CKhQUV1BuV1qZXqhRfaqDACOWz43sGnlsxxLIQdoY8tPWb/EghMIaFQZqBc+Rm7PAomUoMMBWLWkcr0cqLMIdI7XcmWtC5YvU2W2EhoOiaLKJeWYx7NZBOxzISX9azC9Nt2Bk8AkCAgGq7QdinWURZFbAH13kNhrnODomettvJdUK5vstSQsNO4fCmedCYKYfG/PSlt1JH3/NlQCSeQHqp57lSWXeZoCqU/JJjbLV+dHwd0KsCU7eEWUfNK3mL2bG9Jpa8/7M1y7SeHTu96vKVqOwqNrSUFlr/ejTpufI8bR4bLolXP9MK3H6OPbGnlU7BkC0vcJ9jirpWFB3qvZkulF4bpQj8/G7gVC6PmWUVcCSR/jlpRQ==";

// Portal vector: no legacy impl exists to match, so the expected bytes were
// computed with Node's crypto.hkdfSync (an implementation independent of both
// @noble and futoin-hkdf — see scripts/capture-vectors.mjs). The address is
// deliberately mixed-case: the expected value is derived from its LOWERCASED
// form, freezing the normalization rule.
const VECTOR_OWNER_SECRET_B64 =
  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
const VECTOR_PORTAL_ADDRESS = "0x00112233445566778899AaBbCcDdEeFf00112233";
const EXPECTED_PORTAL_SEED_HEX =
  "e0a0e24afb82c899ea9b53a17fcca8b0b152f25a4a7e0e4a10e11560255f6077";

const utf8 = (s: string) => new TextEncoder().encode(s);

describe("Cross-implementation derivation vectors (captured from futoin-hkdf)", () => {
  it("reproduces the app's MASTER_KEY derivation byte-for-byte", () => {
    // Proves whole-family equivalence: if this matches, every label matches.
    const out = deriveHKDFKey(
      utf8(VECTOR_AG2_HASH),
      VECTOR_SALT,
      utf8("MASTER_KEY")
    );
    expect(bytesToHex(out)).toBe(EXPECTED_MASTER_KEY_HEX);
  });

  it("derives the pinned PQ identity seed", () => {
    const seed = deriveIdentityPqSeed(VECTOR_AG2_HASH, VECTOR_SALT);
    expect(bytesToHex(seed)).toBe(EXPECTED_IDENTITY_SEED_HEX);
    expect(seed.length).toBe(SEED_LEN);
  });

  it("string-IKM quirk is load-bearing: decoding the base64 first derives a DIFFERENT key", () => {
    const wrong = deriveHKDFKey(
      toUint8Array(VECTOR_AG2_HASH),
      VECTOR_SALT,
      utf8(HKDF_INFO_IDENTITY_PQ)
    );
    expect(bytesToHex(wrong)).not.toBe(EXPECTED_IDENTITY_SEED_HEX);
  });

  it("chains to the pinned X-Wing public key", async () => {
    const kp = await deriveIdentityPqKeyPair(VECTOR_AG2_HASH, VECTOR_SALT);
    expect(fromUint8Array(kp.publicKey)).toBe(EXPECTED_IDENTITY_PUBLIC_KEY_B64);
    expect(bytesToHex(kp.privateKey)).toBe(EXPECTED_IDENTITY_SEED_HEX);
  });

  it("derives the pinned portal seed (address casing must not matter)", () => {
    const seed = derivePortalPqSeed(
      VECTOR_OWNER_SECRET_B64,
      VECTOR_PORTAL_ADDRESS
    );
    expect(bytesToHex(seed)).toBe(EXPECTED_PORTAL_SEED_HEX);
    const lower = derivePortalPqSeed(
      VECTOR_OWNER_SECRET_B64,
      VECTOR_PORTAL_ADDRESS.toLowerCase()
    );
    expect(bytesToHex(lower)).toBe(EXPECTED_PORTAL_SEED_HEX);
  });
});

describe("Frozen invariants (renaming any of these breaks accounts)", () => {
  it("pins the literal constants", () => {
    expect(IDENTITY_PQ_TAG).toBe("FVPQID1");
    expect(HKDF_INFO_IDENTITY_PQ).toBe("PQ_IDENTITY_KEY");
    expect(HKDF_INFO_PORTAL_PQ).toBe("PQ_PORTAL_KEY");
    expect(XWING_PUBLIC_KEY_LEN).toBe(1216);
    expect(SEED_LEN).toBe(32);
  });
});
