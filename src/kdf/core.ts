import { EncodedReturnType, EncodingType } from "../types";
import { hkdf } from "@noble/hashes/hkdf";
import { DEFAULT_KEY_LENGTH } from "../constants";
import { encodeData } from "../utils/encoding";
import { sha256 } from "@noble/hashes/sha2";
import { pbkdf2, Pbkdf2Opt } from "@noble/hashes/pbkdf2";
import { KDFInput } from "@noble/hashes/utils";
import { cbc } from "@noble/ciphers/aes";
import { generateRandomBytes } from "../utils";
import { AesCbcInputs } from "./types";

// AES block size is 16 bytes (128 bits)
const CBC_IV_LENGTH = 16;

export const deriveHKDFKey = <E extends EncodingType = "bytes">(
  keyMaterial: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  encoding?: E
): EncodedReturnType<E> => {
  const key = hkdf(sha256, keyMaterial, salt, info, DEFAULT_KEY_LENGTH);
  const encodeTo = encoding || ("bytes" as E);

  return encodeData(key, encodeTo);
};

export const derivePBKDF2Key = <E extends EncodingType = "bytes">(
  ikm: KDFInput,
  salt: KDFInput,
  encoding?: E,
  opts?: Pbkdf2Opt
): EncodedReturnType<E> => {
  const pbkdfOpts = opts || { c: 32, dkLen: DEFAULT_KEY_LENGTH };
  const key = pbkdf2(sha256, ikm, salt, pbkdfOpts);
  const encodeTo = encoding || ("bytes" as E);
  return encodeData(key, encodeTo);
};

export const encryptAesCBC = <E extends EncodingType = "bytes">(
  inputs: AesCbcInputs,
  returnFormat?: E
): { iv: EncodedReturnType<E>; cipherText: EncodedReturnType<E> } => {
  const { key, message, iv } = inputs;
  const actualIv = iv || generateRandomBytes(CBC_IV_LENGTH);

  const cipher = cbc(key, actualIv);
  const ciphertext = cipher.encrypt(message);

  const encodeTo = returnFormat || ("bytes" as E);
  return {
    iv: encodeData(actualIv, encodeTo),
    cipherText: encodeData(ciphertext, encodeTo),
  };
};

export const decryptAesCBC = (
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array => {
  const decipher = cbc(key, iv);
  return decipher.decrypt(ciphertext);
};
