import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";

export const CURVE = secp256k1; // Curve to use
export const KDF_HASH = sha256; // Hash for HKDF
export const KEY_LEN = 32; // AES-256 key length
export const NONCE_LEN = 12; // AES-GCM standard nonce length (96 bits)
export const INFO = new TextEncoder().encode("ECIES-AES256-GCM-SHA256"); // Info for HKDF
