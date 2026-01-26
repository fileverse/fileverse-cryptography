import { secp256k1 } from "@noble/curves/secp256k1.js";
export const NONCE_LEN = 12; // AES-GCM standard nonce length (96 bits)
export const INFO = new TextEncoder().encode("ECIES-AES256-GCM-SHA256"); // Info for HKDF
export const CURVE = secp256k1; // secp256k1 is the default curve for ECIES
