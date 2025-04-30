import { hkdf } from "@noble/hashes/hkdf";
import { gcm } from "@noble/ciphers/aes";
import { randomBytes, bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { CURVE, KDF_HASH, KEY_LEN, NONCE_LEN, INFO } from "./config";

export interface EciesCiphertext {
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
  mac: string;
}

export async function encrypt(
  recipientPublicKeyHex: string,
  message: Uint8Array
): Promise<EciesCiphertext> {
  const recipientPublicKey = hexToBytes(recipientPublicKeyHex);

  const ephemeralPrivateKey = CURVE.utils.randomPrivateKey();
  const ephemeralPublicKeyBytes = CURVE.getPublicKey(ephemeralPrivateKey);

  const sharedSecret = CURVE.getSharedSecret(
    ephemeralPrivateKey,
    recipientPublicKey
  );

  const derivedKey = hkdf(
    KDF_HASH,
    sharedSecret,
    ephemeralPublicKeyBytes,
    INFO,
    KEY_LEN
  );

  const nonce = randomBytes(NONCE_LEN);
  const aesGcm = gcm(derivedKey, nonce);
  const ciphertext = aesGcm.encrypt(message);

  const ciphertextBytes = ciphertext.slice(0, ciphertext.length - 16);
  const macBytes = ciphertext.slice(ciphertext.length - 16);

  return {
    ephemeralPublicKey: bytesToHex(ephemeralPublicKeyBytes),
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertextBytes),
    mac: bytesToHex(macBytes),
  };
}
