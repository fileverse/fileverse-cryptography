export * from "./argon";
export * from "./constants";
export * from "./ecies";
export * from "./kdf";
export * from "./nacl";
export * from "./utils";
export * from "./webcrypto";

// PQ module: re-exported by name (not `export *`) to avoid root-barrel
// collisions with ECIES, which also exports `getPublicKey` and
// `CipherTextFormat`. The full PQ surface — including those two and the suite
// constants — is available unambiguously via the `@fileverse/crypto/pq`
// subpath export.
export { generatePqKeyPair, pqEncrypt, pqDecrypt, parsePqCipherString } from "./pq";
export type {
  PqCipher,
  PqKeyPair,
  PqKeyPairBase64,
  PqKeyPairBytes,
  PqKeyPairType,
} from "./pq";

export type { EncodedReturnType, EncodingType } from "./types";

// Identity module: re-exported by name (same collision policy as pq above).
// Full surface via the `@fileverse/crypto/identity` subpath.
export {
  encodeIdentityPublicKey,
  decodeIdentityPublicKey,
  deriveIdentityPqSeed,
  deriveIdentityPqKeyPair,
  derivePortalPqSeed,
  matchesOnchainIdentityKey,
  IDENTITY_PQ_TAG,
} from "./identity";
export type { DecodedIdentityPublicKey } from "./identity";
