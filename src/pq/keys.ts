import { generateRandomBytes } from "../utils";
import { encodeData } from "../utils/encoding";
import { xwingKem } from "./config";
import type { EncodingType, EncodedReturnType } from "../types";
import type { PqKeyPairType } from "./types";

// X-Wing decapsulation-key length. The 32-byte seed IS the private key — X-Wing
// re-expands the keypair from it deterministically — so the boundary
// `privateKey` is this seed and the keypair is recomputed on demand, mirroring
// the ECIES module's `generateECKeyPair(seed)` contract.
const SEED_LEN = 32;

export const generatePqKeyPair = async <E extends EncodingType = "bytes">(
  seed?: Uint8Array,
  encoding?: E
): Promise<PqKeyPairType<E>> => {
  if (seed && seed.length !== SEED_LEN) {
    throw new Error("Invalid seed length");
  }

  // Copy the seed: upstream reads the raw backing ArrayBuffer, so a subarray
  // view of a larger buffer would be rejected there despite passing the length
  // check above — and returning the caller's own array as the private key
  // would alias it (mutating either would corrupt the other).
  const privateKey = seed ? Uint8Array.from(seed) : generateRandomBytes(SEED_LEN);
  const keyPair = await xwingKem.generateKeyPairDerand(privateKey);
  const publicKey = new Uint8Array(
    await xwingKem.serializePublicKey(keyPair.publicKey)
  );

  const actualEncoding = encoding || ("bytes" as E);

  return {
    publicKey: encodeData(publicKey, actualEncoding),
    privateKey: encodeData(privateKey, actualEncoding),
  } as PqKeyPairType<E>;
};

export const getPublicKey = async <E extends EncodingType = "bytes">(
  privateKey: Uint8Array,
  encoding?: E
): Promise<EncodedReturnType<E>> => {
  if (privateKey.length !== SEED_LEN) {
    throw new Error("Invalid private key length");
  }

  // Copy for the same backing-buffer reason as generatePqKeyPair.
  const keyPair = await xwingKem.generateKeyPairDerand(Uint8Array.from(privateKey));
  const publicKey = new Uint8Array(
    await xwingKem.serializePublicKey(keyPair.publicKey)
  );
  return encodeData(publicKey, encoding || ("bytes" as E));
};
