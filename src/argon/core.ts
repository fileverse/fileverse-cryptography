import { argon2idAsync, ArgonOpts } from "@noble/hashes/argon2.js";
import { EncodedReturnType, EncodingType } from "../types";
import { encodeData } from "../utils/encoding";
import { DEFAULT_ARGON_OPTS } from "./config";

export const getArgon2idHash = async <E extends EncodingType = "bytes">(
  password: string,
  salt: Uint8Array,
  returnFormat?: E,
  opts?: ArgonOpts
): Promise<EncodedReturnType<E>> => {
  const actualOpts = opts || DEFAULT_ARGON_OPTS;
  const hash = await argon2idAsync(password, salt, actualOpts);
  const encodeTo = returnFormat || ("bytes" as E);
  return encodeData(hash, encodeTo);
};
