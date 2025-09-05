import { encodeData, toBytes } from "../utils/encoding";
import { CURVE } from "./config";
import type { EncodingType, EncodedReturnType } from "../types";
import type { EciesKeyPairType } from "./types";

export const generateECKeyPair = <E extends EncodingType = "bytes">(
  encoding?: E
): EciesKeyPairType<E> => {
  const privateKey = CURVE.utils.randomPrivateKey();
  const publicKey = CURVE.getPublicKey(privateKey);

  const actualEncoding = encoding || ("bytes" as E);

  return {
    publicKey: encodeData(publicKey, actualEncoding),
    privateKey: encodeData(privateKey, actualEncoding),
  } as EciesKeyPairType<E>;
};

export const deriveSharedSecret = <E extends EncodingType = "bytes">(
  privateKey: Uint8Array | string,
  publicKey: Uint8Array | string,
  encoding?: E
): EncodedReturnType<E> => {
  const privateKeyBytes =
    typeof privateKey === "string" ? toBytes(privateKey) : privateKey;

  const publicKeyBytes =
    typeof publicKey === "string" ? toBytes(publicKey) : publicKey;

  const sharedSecret = CURVE.getSharedSecret(privateKeyBytes, publicKeyBytes);

  return encodeData(sharedSecret, encoding || ("bytes" as E));
};

export const getPublicKey = <E extends EncodingType = "bytes">(
  privateKey: Uint8Array,
  encoding?: E
): EncodedReturnType<E> => {
  return encodeData(CURVE.getPublicKey(privateKey), encoding || ("bytes" as E));
};
