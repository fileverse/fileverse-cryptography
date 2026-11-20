import { EncodingType } from "../types";

export interface PqCipher {
  version: string; // self-describing wire tag (suite id)
  enc: string; // X-Wing KEM encapsulated key (base64)
  ciphertext: string; // AES-256-GCM ciphertext, auth tag included (base64)
}

export interface PqKeyPairBase64 {
  publicKey: string;
  privateKey: string;
}

export interface PqKeyPairBytes {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export type PqKeyPair = PqKeyPairBase64 | PqKeyPairBytes;

export type PqKeyPairType<E extends EncodingType> = E extends "bytes"
  ? PqKeyPairBytes
  : PqKeyPairBase64;

export type CipherTextFormat = "raw" | "base64";
