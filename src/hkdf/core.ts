import { EncodedReturnType, EncodingType } from "../types";
import { hkdf } from "@noble/hashes/hkdf";
import { HKDF_KEY_LENGTH } from "../constants";
import { encodeData } from "../utils/encoding-utils";
import { sha256 } from "@noble/hashes/sha2";

export const deriveHKDFKey = <E extends EncodingType = "bytes">(
  keyMaterial: string,
  salt: Uint8Array,
  info: Uint8Array,
  encoding?: E
): EncodedReturnType<E> => {
  const key = hkdf(sha256, keyMaterial, salt, info, HKDF_KEY_LENGTH);
  const encodeTo = encoding || ("bytes" as E);

  return encodeData(key, encodeTo);
};
