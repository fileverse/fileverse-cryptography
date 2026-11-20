import { SEPARATOR } from "../constants";
import { bytesToBase64, toBytes } from "../utils";
import {
  cipherSuite,
  INFO_BYTES,
  VERSION,
  VERSION_AAD,
  xwingKem,
} from "./config";
import { CipherTextFormat, PqCipher } from "./types";

// X-Wing decapsulation-key length (the private key is the 32-byte seed).
const PRIVATE_KEY_LEN = 32;

// AES-256-GCM appends a 16-byte auth tag, so no valid ciphertext is shorter.
const MIN_CIPHERTEXT_LEN = 16;

// Canonical base64 length of a valid encapsulated key. Checked before any
// decoding so an oversized hostile `enc` part is rejected in O(1).
const ENC_BASE64_LEN = Math.ceil(xwingKem.encSize / 3) * 4;

// HPKE (RFC 9180) single-shot seal/open over the X-Wing hybrid KEM.
//
// The wire cipher is `version · enc · ciphertext` — three parts:
//   - `enc`        : the X-Wing KEM encapsulated key (fresh per message; this
//                    supplies the per-message freshness a nonce gives a raw AEAD).
//   - `ciphertext` : the AES-256-GCM output with the 16-byte auth tag appended.
// There is no nonce on the wire: HPKE derives the AEAD nonce inside its key
// schedule from the KEM shared secret, and the recipient recomputes it. A wrong
// or forged `enc` yields a different key, so decryption fails at the AEAD tag
// check (it never reveals plaintext) — never use the result before `open`.
//
// The version tag is additionally bound as AEAD associated data, so a modified
// tag is rejected cryptographically, not only by the string checks below.

// The default base64 decoder (js-base64) is lenient: it strips foreign
// characters and accepts the URL-safe alphabet, which would give one
// ciphertext unboundedly many wire representations. Requiring that a part
// re-encodes to itself pins the single canonical form our encoder emits.
// NOTE: canonical means standard-alphabet, padded base64 — anything producing
// wire parts must use bytesToBase64 with urlSafe=false (the default), or the
// module will reject its own output.
const isCanonicalBase64 = (part: string): boolean =>
  bytesToBase64(toBytes(part)) === part;

// Validates a PqCipher's shape and encoding (both wire-string and object
// inputs go through this) and returns the decoded parts.
const validatePqCipher = (
  cipher: PqCipher
): { enc: Uint8Array; ciphertext: Uint8Array } => {
  const { version, enc, ciphertext } = cipher;

  if (
    typeof version !== "string" ||
    typeof enc !== "string" ||
    typeof ciphertext !== "string" ||
    !version ||
    !enc ||
    !ciphertext
  ) {
    throw new Error("Missing required parts in encrypted data");
  }

  if (version !== VERSION) {
    throw new Error("Unsupported cipher version");
  }

  // Cheap pre-check before any decoding bounds the work a hostile oversized
  // `enc` can cause; the decoded-length check below stays as the authority.
  if (enc.length !== ENC_BASE64_LEN) {
    throw new Error("Invalid encapsulated key length");
  }

  if (!isCanonicalBase64(enc) || !isCanonicalBase64(ciphertext)) {
    throw new Error("Invalid encrypted data encoding");
  }

  const encBytes = toBytes(enc);
  if (encBytes.length !== xwingKem.encSize) {
    throw new Error("Invalid encapsulated key length");
  }

  const ciphertextBytes = toBytes(ciphertext);
  if (ciphertextBytes.length < MIN_CIPHERTEXT_LEN) {
    throw new Error("Invalid ciphertext length");
  }

  return { enc: encBytes, ciphertext: ciphertextBytes };
};

export const pqEncrypt = async <T extends CipherTextFormat = "base64">(
  publicKey: Uint8Array,
  message: Uint8Array,
  returnFormat?: T
): Promise<T extends "raw" ? PqCipher : string> => {
  const recipientPublicKey = await xwingKem.deserializePublicKey(publicKey);

  const { enc, ct } = await cipherSuite.seal(
    { recipientPublicKey, info: INFO_BYTES },
    message,
    VERSION_AAD
  );

  const encBase64 = bytesToBase64(new Uint8Array(enc));
  const ciphertextBase64 = bytesToBase64(new Uint8Array(ct));

  const actualFormat = returnFormat || ("base64" as T);

  if (actualFormat === "raw") {
    return {
      version: VERSION,
      enc: encBase64,
      ciphertext: ciphertextBase64,
    } as T extends "raw" ? PqCipher : string;
  }

  return (VERSION +
    SEPARATOR +
    encBase64 +
    SEPARATOR +
    ciphertextBase64) as T extends "raw" ? PqCipher : string;
};

export const parsePqCipherString = (concatenatedData: string): PqCipher => {
  const parts = concatenatedData.split(SEPARATOR);
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted data format");
  }

  const [version, enc, ciphertext] = parts;

  if (!version || !enc || !ciphertext) {
    throw new Error("Missing required parts in encrypted data");
  }

  const cipher: PqCipher = { version, enc, ciphertext };

  validatePqCipher(cipher);

  return cipher;
};

export const pqDecrypt = async <T extends PqCipher | string>(
  privateKey: Uint8Array,
  encryptedData: T
): Promise<Uint8Array> => {
  if (privateKey.length !== PRIVATE_KEY_LEN) {
    throw new Error("Invalid private key length");
  }

  const structuredData: PqCipher =
    typeof encryptedData === "string"
      ? parsePqCipherString(encryptedData)
      : encryptedData;

  // For string input this re-validates what parsePqCipherString already
  // checked — deliberate defense-in-depth so the object path can never drift
  // from the string path; the redundant decode is negligible next to the KEM.
  const { enc, ciphertext } = validatePqCipher(structuredData);

  const recipientKey = await xwingKem.deserializePrivateKey(
    Uint8Array.from(privateKey)
  );

  const decryptedMessage = await cipherSuite.open(
    { recipientKey, enc, info: INFO_BYTES },
    ciphertext,
    VERSION_AAD
  );

  return new Uint8Array(decryptedMessage);
};
