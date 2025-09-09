import { Crypto } from "@peculiar/webcrypto";

// Setup crypto with polyfill fallback
function setupCrypto(): {
  webcrypto: Crypto;
  randomBytes: (size: number) => Uint8Array;
} {
  // Try Node.js built-in crypto first
  try {
    const nodeCrypto = require("crypto");
    if (nodeCrypto.webcrypto && nodeCrypto.randomBytes) {
      return {
        webcrypto: nodeCrypto.webcrypto,
        randomBytes: (size: number) => nodeCrypto.randomBytes(size),
      };
    }
  } catch (error) {
    // Node.js crypto not available, continue
  }

  // Try global crypto (modern browsers/environments)
  if (
    typeof globalThis !== "undefined" &&
    globalThis.crypto &&
    globalThis.crypto.subtle
  ) {
    return {
      webcrypto: globalThis.crypto,
      randomBytes: (size: number) => {
        const bytes = new Uint8Array(size);
        globalThis.crypto.getRandomValues(bytes);
        return bytes;
      },
    };
  }

  // Fallback to polyfill
  const polyfillCrypto = new Crypto();
  return {
    webcrypto: polyfillCrypto,
    randomBytes: (size: number) => {
      const bytes = new Uint8Array(size);
      polyfillCrypto.getRandomValues(bytes);
      return bytes;
    },
  };
}

// Initialize crypto on module load
const cryptoSetup = setupCrypto();

export const webcrypto = cryptoSetup.webcrypto;
export const randomBytes = cryptoSetup.randomBytes;
