import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "@noble/hashes/utils";
import { NONCE_LEN, INFO, CURVE } from "./config";
import { base64ToBytes, bytesToBase64 } from "../utils";
import { EciesCipher } from ".";
import { deriveSharedSecret } from "./keys";
import { SEPERATOR } from "../constants";
import { CipherTextFormat } from "./types";
import { deriveHKDFKey } from "../hkdf";
export const eciesEncrypt = <T extends CipherTextFormat = "base64">(
  publicKeyB64: string,
  message: Uint8Array,
  returnFormat?: T
): T extends "raw" ? EciesCipher : string => {
  const recipientPublicKey = base64ToBytes(publicKeyB64);

  const ephemeralPrivateKey = CURVE.utils.randomPrivateKey();
  const ephemeralPublicKeyBytes = CURVE.getPublicKey(ephemeralPrivateKey);

  const sharedSecret = deriveSharedSecret(
    ephemeralPrivateKey,
    recipientPublicKey
  );

  const derivedKey = deriveHKDFKey(sharedSecret, ephemeralPublicKeyBytes, INFO);

  const nonce = randomBytes(NONCE_LEN);
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
    SEPERATOR +
    nonceBase64 +
    SEPERATOR +
    ciphertextBase64 +
    SEPERATOR +
    macBase64) as T extends "raw" ? EciesCipher : string;
};

export const parseEciesCipherString = (
  concatenatedData: string
): EciesCipher => {
  const parts = concatenatedData.split(SEPERATOR);
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
  privateKeyB64: string,
  encryptedData: T
): Uint8Array => {
  const recipientPrivateKey = base64ToBytes(privateKeyB64);

  let structuredData: EciesCipher;

  if (typeof encryptedData === "string") {
    structuredData = parseEciesCipherString(encryptedData);
  } else {
    structuredData = encryptedData;
  }

  const ephemeralPublicKey = base64ToBytes(structuredData.ephemeralPublicKey);
  const nonce = base64ToBytes(structuredData.nonce);
  const ciphertext = base64ToBytes(structuredData.ciphertext);
  const mac = base64ToBytes(structuredData.mac);

  const sharedSecret = deriveSharedSecret(
    recipientPrivateKey,
    ephemeralPublicKey
  );

  const derivedKey = deriveHKDFKey(sharedSecret, ephemeralPublicKey, INFO);

  const ciphertextWithMac = new Uint8Array(ciphertext.length + mac.length);
  ciphertextWithMac.set(ciphertext, 0);
  ciphertextWithMac.set(mac, ciphertext.length);

  const aesGcm = gcm(derivedKey, nonce);
  const decryptedMessage = aesGcm.decrypt(ciphertextWithMac);

  return decryptedMessage;
};
