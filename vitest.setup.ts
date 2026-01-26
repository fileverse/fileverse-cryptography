import { webcrypto } from "node:crypto";

const cryptoValue = globalThis.crypto as unknown as Crypto | undefined;

if (!cryptoValue?.getRandomValues) {
  (globalThis as unknown as { crypto: Crypto }).crypto = webcrypto as unknown as Crypto;
}

