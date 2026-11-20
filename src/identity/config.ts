import { xwingKem } from "../pq/config";

// Tag prefixed to the PQ-format identity accountPublicKey blob (onchain).
// Legacy blobs are RSA SPKI DER and always begin 0x30 0x82, so the formats
// can never collide. FROZEN — changing this orphans every rotated identity.
export const IDENTITY_PQ_TAG = "FVPQID1";
export const IDENTITY_PQ_TAG_BYTES: Uint8Array = new TextEncoder().encode(
  IDENTITY_PQ_TAG
);

// HKDF domain-separation labels. Siblings of the consuming app's existing
// MASTER_KEY / SIGNING_KEY / AGENT_KEY family (same ikm + salt, different
// info). Unversioned to match that family's style; format versioning lives
// in the blob tag above. FROZEN.
export const HKDF_INFO_IDENTITY_PQ = "PQ_IDENTITY_KEY";
export const HKDF_INFO_PORTAL_PQ = "PQ_PORTAL_KEY";

export const SEED_LEN = 32;

// Input-shape pins for the strict validators in derive.ts, verified against
// the consuming app: ag2Hash = base64 of a 32-byte argon2id hash (dkLen 32);
// ownerSecret = base64pad export of the portal's 64-byte ed25519 secret.
export const AG2_HASH_DECODED_LEN = 32;
export const OWNER_SECRET_DECODED_LEN = 64;

// 1216 for X-Wing; sourced from the KEM instance so it can never drift from
// the pq module, and pinned to the literal by a freeze test.
export const XWING_PUBLIC_KEY_LEN: number = xwingKem.publicKeySize;
