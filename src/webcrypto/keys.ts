import { webcrypto } from "./crypto-setup";
import { encodeData } from "../utils/encoding";
import { DEFAULT_AES_KEY_SIZE, DEFAULT_RSA_KEY_SIZE } from "./config";
import { EncodingType } from "../types";
import { RsaKeyPairType } from "./types";

export const generateAESKey = async (
  length: number = DEFAULT_AES_KEY_SIZE
): Promise<CryptoKey> => {
  const key = await webcrypto.subtle.generateKey(
    { name: "AES-GCM", length },
    true,
    ["encrypt", "decrypt"]
  );

  return key;
};

export const exportAESKey = async <E extends "base64" | "bytes" = "bytes">(
  key: CryptoKey,
  encoding?: E
): Promise<E extends "base64" ? string : Uint8Array> => {
  const rawKey = await webcrypto.subtle.exportKey("raw", key);

  const actualReturnFormat = encoding || "bytes";

  return encodeData(
    new Uint8Array(rawKey),
    actualReturnFormat
  ) as E extends "base64" ? string : Uint8Array;
};

export const toAESKey = async (keyBytes: Uint8Array): Promise<CryptoKey> => {
  const key = await webcrypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    {
      name: "AES-GCM",
    },
    true,
    ["encrypt", "decrypt"]
  );

  return key;
};

export const generateRSAKeyPair = async <E extends EncodingType = "base64">(
  keySize: number = DEFAULT_RSA_KEY_SIZE,
  encoding?: E
): Promise<RsaKeyPairType<E>> => {
  const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const actualEncoding = encoding || ("base64" as E);

  const publicKeyBytes = new Uint8Array(
    await webcrypto.subtle.exportKey("spki", publicKey)
  );
  const privateKeyBytes = new Uint8Array(
    await webcrypto.subtle.exportKey("pkcs8", privateKey)
  );

  return {
    publicKey: encodeData(publicKeyBytes, actualEncoding),
    privateKey: encodeData(privateKeyBytes, actualEncoding),
  } as RsaKeyPairType<E>;
};

export const toRSAKey = async (
  keyBytes: Uint8Array,
  format: "pkcs8" | "spki"
): Promise<CryptoKey> => {
  const keyUsage =
    format === "pkcs8" ? ["decrypt" as const] : ["encrypt" as const];

  const key = await webcrypto.subtle.importKey(
    format,
    keyBytes as BufferSource,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    keyUsage
  );

  return key;
};
