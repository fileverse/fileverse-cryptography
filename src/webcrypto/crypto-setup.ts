const cryptoInstance = globalThis.crypto;

if (!cryptoInstance?.subtle) {
  throw new Error(
    "Web Crypto API not available. This package requires a runtime with globalThis.crypto.subtle (browsers, Node 19+, Cloudflare Workers, Deno)."
  );
}

export const webcrypto = cryptoInstance;

export const randomBytes = (size: number): Uint8Array => {
  const bytes = new Uint8Array(size);
  cryptoInstance.getRandomValues(bytes);
  return bytes;
};
