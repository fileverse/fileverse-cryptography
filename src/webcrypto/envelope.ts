import { SEPARATOR } from "../constants";
import { toBytes } from "../utils/encoding";
import { aesDecrypt, aesEncrypt, rsaDecrypt, rsaEncrypt } from "./core";
import { exportAESKey, generateAESKey, toAESKey } from "./keys";

export const encryptEnvelope = async (
  publicKey: Uint8Array,
  message: Uint8Array
): Promise<string> => {
  const aesKey = await generateAESKey();
  const encryptedMessage = await aesEncrypt(aesKey, message, "base64");
  const aesKeyBytes = await exportAESKey(aesKey);
  const encryptedAesKey = await rsaEncrypt(publicKey, aesKeyBytes, "base64");

  return encryptedAesKey + SEPARATOR + encryptedMessage;
};

export const decryptEnvelope = async (
  privateKey: Uint8Array,
  envelopedCipher: string
): Promise<Uint8Array> => {
  const [encryptedAesKey, encryptedMessage] = envelopedCipher.split(SEPARATOR);

  if (!encryptedMessage || !encryptedAesKey) {
    throw new Error("Invalid encrypted message");
  }

  const aesKey = await toAESKey(
    await rsaDecrypt(privateKey, toBytes(encryptedAesKey))
  );

  const message = await aesDecrypt(aesKey, toBytes(encryptedMessage));
  return message;
};
