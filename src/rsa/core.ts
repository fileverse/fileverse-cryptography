import { randomBytes, webcrypto } from "crypto";
import { toRSAKey } from "./keys";
import { DEFAULT_NONCE_LENGTH } from "./config";
import { encodeData, toBytes } from "../utils/encoding-utils";
import { concatBytes } from "@noble/ciphers/utils";
import {
  aesDecrypt,
  aesEncrypt,
  exportAESKey,
  generateRandomAESKey,
  toAESKey,
} from "./envelope-helpers";
import { SEPERATOR } from "../constants";

export const rsaEncrypt = async <E extends "base64" | "bytes" = "base64">(
  publicKey: Uint8Array,
  message: Uint8Array,
  returnFormat?: E
): Promise<E extends "base64" ? string : Uint8Array> => {
  const key = await toRSAKey(publicKey, "spki");

  const nonce = randomBytes(DEFAULT_NONCE_LENGTH);

  const ciphertext = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
      iv: nonce,
    },
    key,
    message
  );

  const cipherTextWithNonce = concatBytes(nonce, new Uint8Array(ciphertext));

  const actualReturnFormat = returnFormat || "base64";

  return encodeData(
    cipherTextWithNonce,
    actualReturnFormat
  ) as E extends "base64" ? string : Uint8Array;
};

export const rsaDecrypt = async (
  privateKey: Uint8Array,
  cipherTextWithNonce: Uint8Array
) => {
  const key = await toRSAKey(privateKey, "pkcs8");
  const nonceBytes = cipherTextWithNonce.slice(0, DEFAULT_NONCE_LENGTH);
  const cipherBytes = cipherTextWithNonce.slice(
    DEFAULT_NONCE_LENGTH,
    cipherTextWithNonce.length
  );

  const decrypted = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
      iv: nonceBytes,
    },
    key,
    cipherBytes
  );

  return new Uint8Array(decrypted);
};

export const rsaEncryptEnvelope = async (
  publicKey: Uint8Array,
  message: Uint8Array
) => {
  const aesKey = await generateRandomAESKey();
  const encryptedMessage = await aesEncrypt(aesKey, message, "base64");
  const aesKeyBytes = await exportAESKey(aesKey);
  const encryptedAesKey = await rsaEncrypt(publicKey, aesKeyBytes, "base64");

  return encryptedMessage + SEPERATOR + encryptedAesKey;
};

export const rsaDecryptEnvelope = async (
  privateKey: Uint8Array,
  envelopedCipher: string
) => {
  const [encryptedMessage, encryptedAesKey] = envelopedCipher.split(SEPERATOR);

  if (!encryptedMessage || !encryptedAesKey) {
    throw new Error("Invalid encrypted message");
  }

  const aesKey = await toAESKey(
    await rsaDecrypt(privateKey, toBytes(encryptedAesKey))
  );

  const message = await aesDecrypt(aesKey, toBytes(encryptedMessage));
  return message;
};
