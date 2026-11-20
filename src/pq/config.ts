import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";

// Self-describing wire tag for the PQ cipher format. Prefixed to every
// `pqEncrypt` string so a blob is routable without external metadata.
// Chosen to never collide with legacy ECIES strings (those always begin with
// "A" — the base64 of a compressed secp256k1 point's 0x02/0x03 lead byte).
// Maps to file-metadata `version: "5"` on the application side.
export const VERSION = "FVPQ1";

// HPKE application context, mixed into the key schedule on both sides. A
// mismatch makes `open` fail, which gives implicit suite-downgrade protection.
// Must be <= 128 bytes (HPKE `info` limit).
// INFO_BYTES is what the module actually feeds the key schedule; it is not
// re-exported from the public barrel. The public INFO is a defensive copy so
// that a consumer writing into it cannot silently break the key schedule.
export const INFO_BYTES = new TextEncoder().encode(
  "FILEVERSE-PQ-HPKE-XWING-v1"
);
export const INFO = Uint8Array.from(INFO_BYTES);

// The wire version tag is also bound as AEAD associated data on every
// seal/open, so a tampered tag is cryptographically rejected — not just
// rejected by string comparison during parsing. Internal-only (not in the
// public barrel).
export const VERSION_AAD = new TextEncoder().encode(VERSION);

// The X-Wing hybrid KEM instance. Exposed on its own (typed as `XWing`) so the
// module can call X-Wing's derandomized keygen (`generateKeyPairDerand`) and
// raw key (de)serialization, which are not part of the generic `KemInterface`.
export const xwingKem = new XWing();

// HPKE (RFC 9180) cipher suite: X-Wing hybrid KEM (ML-KEM-768 + X25519),
// HKDF-SHA256, AES-256-GCM.
export const cipherSuite = new CipherSuite({
  kem: xwingKem,
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

// Descriptive suite identifier (for documentation / introspection parity with
// the ECIES module's exported config).
export const SUITE = {
  kem: "X-Wing",
  kdf: "HKDF-SHA256",
  aead: "AES-256-GCM",
} as const;
