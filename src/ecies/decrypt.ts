import { hkdf } from "@noble/hashes/hkdf";
import { gcm } from "@noble/ciphers/aes";
import { concatBytes, hexToBytes } from "@noble/hashes/utils";
import { CURVE, KDF_HASH, KEY_LEN, INFO } from "./config";
import type { EciesCiphertext } from "./encrypt";

export async function decrypt(
  recipientPrivateKeyHex: string,
  encryptedData: EciesCiphertext
): Promise<Uint8Array | null> {
  const recipientPrivateKey = hexToBytes(recipientPrivateKeyHex);
  const ephemeralPublicKey = hexToBytes(encryptedData.ephemeralPublicKey);
  const nonce = hexToBytes(encryptedData.nonce);
  const ciphertext = hexToBytes(encryptedData.ciphertext);
  const mac = hexToBytes(encryptedData.mac);

  const ciphertextWithMac = concatBytes(ciphertext, mac);

  const sharedSecret = CURVE.getSharedSecret(
    recipientPrivateKey,
    ephemeralPublicKey
  );

  const derivedKey = hkdf(
    KDF_HASH,
    sharedSecret,
    ephemeralPublicKey,
    INFO,
    KEY_LEN
  );

  try {
    const aesGcm = gcm(derivedKey, nonce);
    const decryptedMessage = await aesGcm.decrypt(ciphertextWithMac);
    return decryptedMessage;
  } catch (error) {
    console.error("ECIES Decryption Failed:", error);
    return null;
  }
}
