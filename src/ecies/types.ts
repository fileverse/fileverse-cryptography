import { EncodingType } from "../types";

export interface EciesCipher {
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
  mac: string;
}

export interface EciesKeyPairBase64 {
  publicKey: string;
  privateKey: string;
}

export interface EciesKeyPairBytes {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export type EciesKeyPair = EciesKeyPairBase64 | EciesKeyPairBytes;

export type EciesKeyPairType<E extends EncodingType> = E extends "bytes"
  ? EciesKeyPairBytes
  : EciesKeyPairBase64;

export type CipherTextFormat = "raw" | "base64";
