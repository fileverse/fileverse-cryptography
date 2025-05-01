export type EncodingType = "base64" | "bytes";

export type EncodedReturnType<E extends EncodingType> = E extends "bytes"
  ? Uint8Array
  : string;
