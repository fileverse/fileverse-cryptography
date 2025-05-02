import { EncodingType } from "../types";

export interface RsaKeyPairBase64 {
  publicKey: string;
  privateKey: string;
}

export interface RsaKeyPairBytes {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export type RsaKeyPair = RsaKeyPairBase64 | RsaKeyPairBytes;

export type RsaKeyPairType<E extends EncodingType> = E extends "bytes"
  ? RsaKeyPairBytes
  : RsaKeyPairBase64;
