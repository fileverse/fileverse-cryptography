import { IDENTITY_PQ_TAG_BYTES, XWING_PUBLIC_KEY_LEN } from "./config";

const TAG_LEN = IDENTITY_PQ_TAG_BYTES.length;
const PQ_BLOB_LEN = TAG_LEN + XWING_PUBLIC_KEY_LEN;

// The first octet of every DER-encoded RSA SPKI public key (ASN.1 SEQUENCE) —
// how every pre-rotation accountPublicKey blob begins.
const DER_SEQUENCE = 0x30;

export interface DecodedIdentityPublicKeyPq {
  format: "pq";
  publicKey: Uint8Array;
}

export interface DecodedIdentityPublicKeyRsa {
  format: "rsa";
  spki: Uint8Array;
}

export type DecodedIdentityPublicKey =
  | DecodedIdentityPublicKeyPq
  | DecodedIdentityPublicKeyRsa;

const startsWithTag = (bytes: Uint8Array): boolean => {
  if (bytes.length < TAG_LEN) return false;
  for (let i = 0; i < TAG_LEN; i++) {
    if (bytes[i] !== IDENTITY_PQ_TAG_BYTES[i]) return false;
  }
  return true;
};

// [ "FVPQID1" (7B) | X-Wing public key (1216B) ] — exactly 1223 bytes.
export const encodeIdentityPublicKey = (
  xwingPublicKey: Uint8Array
): Uint8Array => {
  if (xwingPublicKey.length !== XWING_PUBLIC_KEY_LEN) {
    throw new Error("Invalid X-Wing public key length");
  }
  const out = new Uint8Array(PQ_BLOB_LEN);
  out.set(IDENTITY_PQ_TAG_BYTES, 0);
  out.set(xwingPublicKey, TAG_LEN);
  return out;
};

// Total and strict: every valid blob (either generation) has exactly one
// parse; anything else throws. An unrecognized identity format is never
// safely ignorable, so there is deliberately no lenient variant.
export const decodeIdentityPublicKey = (
  bytes: Uint8Array
): DecodedIdentityPublicKey => {
  if (startsWithTag(bytes)) {
    if (bytes.length !== PQ_BLOB_LEN) {
      throw new Error("Invalid PQ identity public key length");
    }
    return { format: "pq", publicKey: bytes.slice(TAG_LEN) };
  }
  if (bytes.length > 0 && bytes[0] === DER_SEQUENCE) {
    return { format: "rsa", spki: Uint8Array.from(bytes) };
  }
  throw new Error("Unknown identity public key format");
};
