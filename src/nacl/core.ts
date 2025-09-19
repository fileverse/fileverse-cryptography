import { SEPARATOR } from "../constants";
import { bytesToBase64, generateRandomBytes, toBytes } from "../utils";
import { SECRET_BOX_KEY_LEN, SECRET_BOX_NONCE_LEN } from "./config";
import { secretbox } from "tweetnacl";

export const secretBoxEncrypt = (
  key: Uint8Array,
  message: Uint8Array,
  urlSafe = false
): string => {
  if (key.length !== SECRET_BOX_KEY_LEN) throw new Error("Invalid key length");

  const nonce = generateRandomBytes(SECRET_BOX_NONCE_LEN);
  const encrypted = secretbox(message, nonce, key);

  return (
    bytesToBase64(nonce, urlSafe) +
    SEPARATOR +
    bytesToBase64(encrypted, urlSafe)
  );
};

export const secretBoxDecrypt = (key: Uint8Array, encrypted: string) => {
  const [nonce, ciphertext] = encrypted.split(SEPARATOR);

  if (!nonce || !ciphertext) throw new Error("Invalid encrypted message");

  if (key.length !== SECRET_BOX_KEY_LEN) throw new Error("Invalid key length");

  const nonceBytes = toBytes(nonce);
  if (nonceBytes.length !== SECRET_BOX_NONCE_LEN)
    throw new Error("Invalid nonce length");

  const decrypted = secretbox.open(toBytes(ciphertext), nonceBytes, key);
  if (!decrypted) throw new Error("Could not decrypt message");

  return decrypted;
};
