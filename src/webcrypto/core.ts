import { randomBytes, webcrypto } from "./crypto-setup";
import { toRSAKey } from "./keys";
import { encodeData } from "../utils/encoding";
import { DEFAULT_NONCE_LENGTH } from "./config";
import { concatBytes } from "@noble/hashes/utils";

export const rsaEncrypt = async <E extends "base64" | "bytes" = "base64">(
  publicKey: Uint8Array,
  message: Uint8Array,
  encoding?: E
): Promise<E extends "base64" ? string : Uint8Array> => {
  const key = await toRSAKey(publicKey, "spki");
  const nonce = randomBytes(DEFAULT_NONCE_LENGTH);

  const ciphertext = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
      iv: nonce as BufferSource,
    },
    key,
    message as BufferSource
  );

  const actualReturnFormat = encoding || "base64";

  const cipherTextWithNonce = concatBytes(nonce, new Uint8Array(ciphertext));
  return encodeData(
    cipherTextWithNonce,
    actualReturnFormat
  ) as E extends "base64" ? string : Uint8Array;
};

export const rsaDecrypt = async (
  privateKey: Uint8Array,
  cipherText: Uint8Array
): Promise<Uint8Array> => {
  const key = await toRSAKey(privateKey, "pkcs8");
  const nonceBytes = cipherText.slice(0, DEFAULT_NONCE_LENGTH);
  const cipherTextBytes = cipherText.slice(
    DEFAULT_NONCE_LENGTH,
    cipherText.length
  );
  const decrypted = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
      iv: nonceBytes as BufferSource,
    },
    key,
    cipherTextBytes as BufferSource
  );

  return new Uint8Array(decrypted);
};

export const aesEncrypt = async <E extends "base64" | "bytes" = "bytes">(
  key: CryptoKey,
  message: Uint8Array,
  encoding?: E
): Promise<E extends "base64" ? string : Uint8Array> => {
  const nonce = randomBytes(DEFAULT_NONCE_LENGTH);

  const ciphertext = new Uint8Array(
    await webcrypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as BufferSource },
      key,
      message as BufferSource
    )
  );

  const cipherTextWithNonce = concatBytes(nonce, ciphertext);

  const actualReturnFormat = encoding || "bytes";

  return encodeData(
    cipherTextWithNonce,
    actualReturnFormat
  ) as E extends "base64" ? string : Uint8Array;
};

export const aesDecrypt = async (
  key: CryptoKey,
  cipherTextWithNonce: Uint8Array
): Promise<Uint8Array> => {
  const nonce = cipherTextWithNonce.slice(0, DEFAULT_NONCE_LENGTH);
  const ciphertext = cipherTextWithNonce.slice(
    DEFAULT_NONCE_LENGTH,
    cipherTextWithNonce.length
  );

  const decrypted = await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    ciphertext as BufferSource
  );

  return new Uint8Array(decrypted);
};
