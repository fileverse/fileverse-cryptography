// Recomputes every pinned derivation vector in
// src/identity/__tests__/vectors.test.ts using implementations this library
// does NOT use, and fails on any mismatch. Run with `npm run capture:vectors`.
//
// Why this exists: the vector test alone cannot prove the string-IKM
// assumption about the consuming app — @noble and futoin-hkdf both implement
// RFC 5869 correctly, so a wrong assumption baked into both the capture and
// the test would still pass. This script IS the capture: it derives the
// expected bytes with futoin-hkdf (the app's HKDF library) using the app's
// exact call shape, quoted below from source.
//
// App source of truth (the consuming app's key-derivation helper):
//
//   const createDerivedKey = (secret: string, salt: Uint8Array, info) => {
//     const { length, hash } = DERIVATION_KEY_CONFIG[info]; // 32, 'SHA-256'
//     const privateKey = hkdf(Buffer.from(secret), length, {
//       salt: Buffer.from(salt),
//       info: Buffer.from(info),
//       hash: hash,
//     });
//     return Uint8Array.from(privateKey);
//   };
//
// The load-bearing quirk: `secret` is the base64 ag2Hash STRING and
// `Buffer.from(string)` takes its UTF-8 bytes — the hash is never base64-
// decoded. The identity PQ seed must mirror this or rotation would derive a
// key unrelated to the account's existing MASTER_KEY family.
//
// The portal seed is a new derivation (no app legacy to match), so its vector
// is cross-checked against Node's built-in crypto.hkdfSync instead — a third
// HKDF implementation independent of both @noble and futoin-hkdf.

import hkdf from "futoin-hkdf";
import { hkdfSync } from "node:crypto";

const hex = (bytes) => Buffer.from(bytes).toString("hex");

// ─── Vector inputs (keep byte-identical to vectors.test.ts) ─────────────────
const VECTOR_AG2_HASH = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const VECTOR_SALT = Buffer.from(
  "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
  "hex"
);
const VECTOR_OWNER_SECRET_B64 =
  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
const VECTOR_PORTAL_ADDRESS = "0x00112233445566778899AaBbCcDdEeFf00112233";

// ─── Pinned expectations (keep byte-identical to vectors.test.ts) ───────────
const EXPECTED = {
  MASTER_KEY:
    "58107ede9d587b268cb585acfc13cc6f522cd2f36cdfb430ea5ba987ce2da4c3",
  PQ_IDENTITY_KEY:
    "9250a62c80c9dbd8266ace57edbfcee59e7e0a3bfa5bfd92a5faabd23ca6e467",
  PQ_PORTAL_KEY:
    "e0a0e24afb82c899ea9b53a17fcca8b0b152f25a4a7e0e4a10e11560255f6077",
};

// The app's createDerivedKey, verbatim call shape (futoin-hkdf).
const appDerive = (secret, salt, info) =>
  Uint8Array.from(
    hkdf(Buffer.from(secret), 32, {
      salt: Buffer.from(salt),
      info: Buffer.from(info),
      hash: "SHA-256",
    })
  );

const results = {
  MASTER_KEY: hex(appDerive(VECTOR_AG2_HASH, VECTOR_SALT, "MASTER_KEY")),
  PQ_IDENTITY_KEY: hex(
    appDerive(VECTOR_AG2_HASH, VECTOR_SALT, "PQ_IDENTITY_KEY")
  ),
  PQ_PORTAL_KEY: hex(
    hkdfSync(
      "sha256",
      Buffer.from(VECTOR_OWNER_SECRET_B64, "base64"),
      Buffer.from(VECTOR_PORTAL_ADDRESS.toLowerCase(), "utf8"),
      Buffer.from("PQ_PORTAL_KEY", "utf8"),
      32
    )
  ),
};

// Demonstrate the quirk is real: decoding the base64 first gives another key.
const decodedIkmVariant = hex(
  hkdfSync(
    "sha256",
    Buffer.from(VECTOR_AG2_HASH, "base64"),
    VECTOR_SALT,
    Buffer.from("PQ_IDENTITY_KEY", "utf8"),
    32
  )
);

let failed = false;
for (const [label, expected] of Object.entries(EXPECTED)) {
  const ok = results[label] === expected;
  if (!ok) failed = true;
  console.log(`${ok ? "OK  " : "FAIL"} ${label}: ${results[label]}`);
  if (!ok) console.log(`     expected: ${expected}`);
}
console.log(
  `note decoded-IKM variant of PQ_IDENTITY_KEY: ${decodedIkmVariant} (must differ)`
);
if (decodedIkmVariant === EXPECTED.PQ_IDENTITY_KEY) {
  console.log("FAIL decoded-IKM variant collides with the pinned seed");
  failed = true;
}

process.exit(failed ? 1 : 0);
