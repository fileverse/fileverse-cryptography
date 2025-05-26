import { webcrypto } from "crypto";
import { EncodingType } from "../types";
import { bytesToBase64, encodeData } from "../utils/encoding";
import { RsaKeyPairType } from "./types";
export const DEFAULT_RSA_KEY_SIZE = 4096;

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
) => {
  const keyUsage =
    format === "pkcs8" ? ["decrypt" as const] : ["encrypt" as const];

  const key = await webcrypto.subtle.importKey(
    format,
    keyBytes,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    keyUsage
  );

  return key;
};
