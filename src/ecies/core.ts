import { gcm } from "@noble/ciphers/aes";
import { NONCE_LEN, INFO, CURVE } from "./config";
import { toBytes, bytesToBase64, generateRandomBytes } from "../utils";
import { EciesCipher } from ".";
import { deriveSharedSecret } from "./keys";
import { SEPARATOR } from "../constants";
import { CipherTextFormat } from "./types";
import { deriveHKDFKey } from "../kdf";

export const eciesEncrypt = <T extends CipherTextFormat = "base64">(
  publicKey: Uint8Array,
  message: Uint8Array,
  returnFormat?: T
): T extends "raw" ? EciesCipher : string => {
  const ephemeralPrivateKey = CURVE.utils.randomPrivateKey();
  const ephemeralPublicKeyBytes = CURVE.getPublicKey(ephemeralPrivateKey);

  const sharedSecret = deriveSharedSecret(ephemeralPrivateKey, publicKey);

  const derivedKey = deriveHKDFKey(sharedSecret, ephemeralPublicKeyBytes, INFO);

  const nonce = generateRandomBytes(NONCE_LEN);
  const aesGcm = gcm(derivedKey, nonce);
  const ciphertext = aesGcm.encrypt(message);

  const ciphertextBytes = ciphertext.slice(0, ciphertext.length - 16);
  const macBytes = ciphertext.slice(ciphertext.length - 16);

  const ephemeralPublicKey = bytesToBase64(ephemeralPublicKeyBytes);
  const nonceBase64 = bytesToBase64(nonce);
  const ciphertextBase64 = bytesToBase64(ciphertextBytes);
  const macBase64 = bytesToBase64(macBytes);

  const actualFormat = returnFormat || ("base64" as T);

  if (actualFormat === "raw") {
    return {
      ephemeralPublicKey,
      nonce: nonceBase64,
      ciphertext: ciphertextBase64,
      mac: macBase64,
    } as T extends "raw" ? EciesCipher : string;
  }

  return (ephemeralPublicKey +
    SEPARATOR +
    nonceBase64 +
    SEPARATOR +
    ciphertextBase64 +
    SEPARATOR +
    macBase64) as T extends "raw" ? EciesCipher : string;
};

export const parseEciesCipherString = (
  concatenatedData: string
): EciesCipher => {
  const parts = concatenatedData.split(SEPARATOR);
  if (parts.length !== 4) {
    throw new Error("Invalid encrypted data format");
  }

  const [ephemeralPublicKey, nonce, ciphertext, mac] = parts;

  if (!ephemeralPublicKey || !nonce || !ciphertext || !mac) {
    throw new Error("Missing required parts in encrypted data");
  }

  return {
    ephemeralPublicKey,
    nonce,
    ciphertext,
    mac,
  };
};

export const eciesDecrypt = <T extends EciesCipher | string>(
  privateKey: Uint8Array,
  encryptedData: T
): Uint8Array => {
  let structuredData: EciesCipher;

  if (typeof encryptedData === "string") {
    structuredData = parseEciesCipherString(encryptedData);
  } else {
    structuredData = encryptedData;
  }

  const ephemeralPublicKey = toBytes(structuredData.ephemeralPublicKey);
  const nonce = toBytes(structuredData.nonce);
  const ciphertext = toBytes(structuredData.ciphertext);
  const mac = toBytes(structuredData.mac);

  const sharedSecret = deriveSharedSecret(privateKey, ephemeralPublicKey);

  const derivedKey = deriveHKDFKey(sharedSecret, ephemeralPublicKey, INFO);

  const ciphertextWithMac = new Uint8Array(ciphertext.length + mac.length);
  ciphertextWithMac.set(ciphertext, 0);
  ciphertextWithMac.set(mac, ciphertext.length);

  const aesGcm = gcm(derivedKey, nonce);
  const decryptedMessage = aesGcm.decrypt(ciphertextWithMac);

  return decryptedMessage;
};
