import { toUint8Array, fromUint8Array } from "js-base64";
import { deriveHKDFKey } from "../kdf";
import { generatePqKeyPair } from "../pq";
import type { PqKeyPairBytes } from "../pq";
import {
  HKDF_INFO_IDENTITY_PQ,
  HKDF_INFO_PORTAL_PQ,
  AG2_HASH_DECODED_LEN,
  OWNER_SECRET_DECODED_LEN,
} from "./config";
import { decodeIdentityPublicKey } from "./codec";

const utf8 = (s: string) => new TextEncoder().encode(s);

// js-base64's toUint8Array never throws — it silently decodes garbage (and
// maps the empty string to zero bytes), which would turn a caller bug into a
// fixed, publicly computable key. So every base64 input is decoded strictly:
// it must re-encode to the identical string (standard alphabet, padded — the
// only form the consuming app produces) and decode to the expected length.
const decodeStrictBase64 = (
  value: string,
  expectedLen: number,
  what: string
): Uint8Array => {
  const bytes = toUint8Array(value);
  if (bytes.length !== expectedLen || fromUint8Array(bytes) !== value) {
    throw new Error(
      `${what} must be standard base64 of exactly ${expectedLen} bytes`
    );
  }
  return bytes;
};

const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

// ⚠ The IKM is the UTF-8 bytes of the base64 ag2Hash STRING — mirroring the
// consuming app's existing derivation family (futoin-hkdf `Buffer.from(ag2Hash)`
// for MASTER_KEY / SIGNING_KEY / AGENT_KEY). Base64-decoding first would derive
// a DIFFERENT key and orphan the account. This quirk is load-bearing and
// enforced by the cross-implementation vector test. The strict decode below is
// validation ONLY — its result is deliberately discarded.
//
// Salt is validated as non-empty but not length-pinned: the app creates 24-byte
// salts but the chain read-back path (`toBytes(toHex(salt))`) does not
// guarantee a fixed width, and rejecting a real stored salt would orphan the
// account at rotation time.
export const deriveIdentityPqSeed = (
  ag2Hash: string,
  salt: Uint8Array
): Uint8Array => {
  decodeStrictBase64(ag2Hash, AG2_HASH_DECODED_LEN, "ag2Hash");
  if (salt.length === 0) {
    throw new Error("salt must not be empty");
  }
  return deriveHKDFKey(utf8(ag2Hash), salt, utf8(HKDF_INFO_IDENTITY_PQ));
};

// The seed is a SIBLING of masterKey (same ikm + salt, different info), not a
// child — masterKey only ever exists as a non-exportable WebCrypto AES key.
export const deriveIdentityPqKeyPair = (
  ag2Hash: string,
  salt: Uint8Array
): Promise<PqKeyPairBytes> =>
  generatePqKeyPair(deriveIdentityPqSeed(ag2Hash, salt));

// Portal seeds are a NEW derivation with no legacy implementation to match,
// so the clean conventions apply: IKM = the DECODED ownerSecret bytes (the
// portal's exported 64-byte ed25519 secret), salt = the portal address, portal
// label. The address salt exists so that an ownerSecret ever duplicated across
// portals (clone, backup restore, migration) still derives distinct keys.
//
// ⚠ FROZEN: the salt is the LOWERCASED address string's UTF-8 bytes — EVM
// addresses circulate in checksummed and lowercase forms, and without
// normalization the same portal would derive different keys per casing.
export const derivePortalPqSeed = (
  ownerSecretBase64: string,
  portalAddress: string
): Uint8Array => {
  const ownerSecret = decodeStrictBase64(
    ownerSecretBase64,
    OWNER_SECRET_DECODED_LEN,
    "ownerSecret"
  );
  if (!EVM_ADDRESS_RE.test(portalAddress)) {
    throw new Error("portalAddress must be a 0x-prefixed 20-byte hex address");
  }
  return deriveHKDFKey(
    ownerSecret,
    utf8(portalAddress.toLowerCase()),
    utf8(HKDF_INFO_PORTAL_PQ)
  );
};

// The login-time drift guard: true iff the freshly derived public key matches
// the onchain blob. A mismatch on a rotated account means derivation drift or
// a non-deterministic wallet — callers must stop and alert, never decrypt.
// Also doubles as rotation detection (format "rsa" → not rotated → false).
export const matchesOnchainIdentityKey = (
  derivedPublicKey: Uint8Array,
  onchainAccountPublicKey: Uint8Array
): boolean => {
  let decoded;
  try {
    decoded = decodeIdentityPublicKey(onchainAccountPublicKey);
  } catch {
    return false;
  }
  if (decoded.format !== "pq") return false;
  const expected = decoded.publicKey;
  if (expected.length !== derivedPublicKey.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= (expected[i] as number) ^ (derivedPublicKey[i] as number);
  }
  return diff === 0;
};
