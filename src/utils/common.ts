import { randomBytes } from "@noble/hashes/utils.js";
import { EncodedReturnType, EncodingType } from "../types";
import { encodeData } from "./encoding";

export const generateRandomBytes = <E extends EncodingType = "bytes">(
  length = 32,
  encoding?: E
): EncodedReturnType<E> => {
  const bytes = randomBytes(length);
  const encodeTo = encoding || ("bytes" as E);
  return encodeData(bytes, encodeTo);
};
