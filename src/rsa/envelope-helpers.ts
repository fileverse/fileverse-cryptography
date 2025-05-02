import { randomBytes, webcrypto } from "crypto";
import { encodeData } from "../utils/encoding-utils";
import { DEFAULT_NONCE_LENGTH } from "./config";
import { concatBytes } from "@noble/hashes/utils";

export const generateRandomAESKey = async () => {
  const key = await webcrypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  return key;
};

export const exportAESKey = async <E extends "base64" | "bytes" = "bytes">(
  key: webcrypto.CryptoKey,
  returnFormat?: E
): Promise<E extends "base64" ? string : Uint8Array> => {
  const rawKey = await webcrypto.subtle.exportKey("raw", key);

  const actualReturnFormat = returnFormat || "bytes";

  return encodeData(
    new Uint8Array(rawKey),
    actualReturnFormat
  ) as E extends "base64" ? string : Uint8Array;
};

export const aesEncrypt = async <E extends "base64" | "bytes" = "bytes">(
  key: webcrypto.CryptoKey,
  message: Uint8Array,
  returnFormat?: E
): Promise<E extends "base64" ? string : Uint8Array> => {
  const nonce = randomBytes(DEFAULT_NONCE_LENGTH);

  const ciphertext = new Uint8Array(
    await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, message)
  );

  const cipherTextWithNonce = concatBytes(nonce, ciphertext);

  const actualReturnFormat = returnFormat || "bytes";

  return encodeData(
    cipherTextWithNonce,
    actualReturnFormat
  ) as E extends "base64" ? string : Uint8Array;
};

export const aesDecrypt = async (
  key: webcrypto.CryptoKey,
  cipherTextWithNonce: Uint8Array
) => {
  const nonce = cipherTextWithNonce.slice(0, DEFAULT_NONCE_LENGTH);
  const ciphertext = cipherTextWithNonce.slice(
    DEFAULT_NONCE_LENGTH,
    cipherTextWithNonce.length
  );

  const decrypted = await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    ciphertext
  );

  return new Uint8Array(decrypted);
};

export const toAESKey = async (keyBytes: Uint8Array) => {
  const key = await webcrypto.subtle.importKey(
    "raw",
    keyBytes,
    {
      name: "AES-GCM",
    },
    true,
    ["encrypt", "decrypt"]
  );

  return key;
};
