import { bytesToHex } from "@noble/hashes/utils";
import { CURVE } from "./config";

export function generateKeyPair(): { publicKey: string; privateKey: string } {
  const privateKey = CURVE.utils.randomPrivateKey();
  const publicKey = CURVE.getPublicKey(privateKey);
  return {
    publicKey: bytesToHex(publicKey),
    privateKey: bytesToHex(privateKey),
  };
}
