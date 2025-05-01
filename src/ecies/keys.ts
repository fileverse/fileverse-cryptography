import { encodeData, base64ToBytes } from "../utils/encoding-utils";
import { CURVE } from "./config";
import type { EncodingType, EncodedReturnType } from "../types";
import type { EciesKeyPairType } from "./types";

export const generateECKeyPair = <E extends EncodingType = "base64">(
  encoding?: E
): EciesKeyPairType<E> => {
  const privateKey = CURVE.utils.randomPrivateKey();
  const publicKey = CURVE.getPublicKey(privateKey);

  const actualEncoding = encoding || ("base64" as E);

  return {
    publicKey: encodeData(publicKey, actualEncoding),
    privateKey: encodeData(privateKey, actualEncoding),
  } as EciesKeyPairType<E>;
};

export const deriveSharedSecret = <E extends EncodingType = "base64">(
  privateKey: Uint8Array | string,
  publicKey: Uint8Array | string,
  encoding?: E
): EncodedReturnType<E> => {
  const privateKeyBytes =
    typeof privateKey === "string" ? base64ToBytes(privateKey) : privateKey;

  const publicKeyBytes =
    typeof publicKey === "string" ? base64ToBytes(publicKey) : publicKey;

  const sharedSecret = CURVE.getSharedSecret(privateKeyBytes, publicKeyBytes);

  return encodeData(sharedSecret, encoding || ("base64" as E));
};
