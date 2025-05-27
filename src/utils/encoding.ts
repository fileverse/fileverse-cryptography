import { fromUint8Array, toUint8Array } from "js-base64";
import { EncodingType, EncodedReturnType } from "../types";

export const toBytes = (base64: string) => toUint8Array(base64);
export const bytesToBase64 = (bytes: Uint8Array, urlSafe = false) =>
  fromUint8Array(bytes, urlSafe);

export function encodeData<E extends EncodingType>(
  data: Uint8Array,
  encoding: E
): EncodedReturnType<E> {
  if (encoding === "bytes") {
    return data as EncodedReturnType<E>;
  }
  return bytesToBase64(data) as EncodedReturnType<E>;
}
