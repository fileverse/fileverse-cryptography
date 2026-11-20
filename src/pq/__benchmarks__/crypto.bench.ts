import { bench, describe } from "vitest";
import {
  eciesEncrypt,
  eciesDecrypt,
  generateECKeyPair,
} from "../../ecies";
import { generatePqKeyPair } from "../keys";
import { pqEncrypt, pqDecrypt } from "../core";
import { generateRSAKeyPair, rsaEncrypt, rsaDecrypt } from "../../webcrypto";
import { toBytes, generateRandomBytes } from "../../utils";

// Mirror real app usage: a portal/identity wraps a 32-byte file key, with the
// keypair derived from a 32-byte seed (portalSeed).
const ecSeed = generateRandomBytes(48); // secp256k1 randomSecretKey needs 48 bytes
const pqSeed = generateRandomBytes(32); // X-Wing seed is exactly 32 bytes
const fileKey = generateRandomBytes(32);

// --- Portal: classical ECIES (secp256k1) vs PQ (HPKE + X-Wing) ---
const ecKeyPair = generateECKeyPair(ecSeed);
const pqKeyPair = await generatePqKeyPair(pqSeed);

const ecCipher = eciesEncrypt(ecKeyPair.publicKey, fileKey);
const pqCipher = await pqEncrypt(pqKeyPair.publicKey, fileKey);

// --- Identity: classical RSA-4096 vs PQ ---
const rsaKeyPair = await generateRSAKeyPair(4096, "bytes");
const rsaCipher = await rsaEncrypt(rsaKeyPair.publicKey, fileKey);

describe("keygen from 32-byte seed (portal — done per-op in KeyStore)", () => {
  bench("classical · generateECKeyPair (secp256k1)", () => {
    generateECKeyPair(ecSeed);
  });
  bench("PQ · generatePqKeyPair (X-Wing)", async () => {
    await generatePqKeyPair(pqSeed);
  });
});

describe("encrypt / wrap a 32-byte file key (portal)", () => {
  bench("classical · eciesEncrypt", () => {
    eciesEncrypt(ecKeyPair.publicKey, fileKey);
  });
  bench("PQ · pqEncrypt", async () => {
    await pqEncrypt(pqKeyPair.publicKey, fileKey);
  });
});

describe("decrypt / unwrap a 32-byte file key (portal)", () => {
  bench("classical · eciesDecrypt", () => {
    eciesDecrypt(ecKeyPair.privateKey, ecCipher);
  });
  bench("PQ · pqDecrypt", async () => {
    await pqDecrypt(pqKeyPair.privateKey, pqCipher);
  });
});

describe("KeyStore.encryptData as used (keygen-from-seed + encrypt)", () => {
  bench("classical · generateECKeyPair + eciesEncrypt", () => {
    const kp = generateECKeyPair(ecSeed);
    eciesEncrypt(kp.publicKey, fileKey);
  });
  bench("PQ · generatePqKeyPair + pqEncrypt", async () => {
    const kp = await generatePqKeyPair(pqSeed);
    await pqEncrypt(kp.publicKey, fileKey);
  });
});

describe("identity keygen (first sign-in)", () => {
  bench("classical · generateRSAKeyPair(4096)", async () => {
    await generateRSAKeyPair(4096, "bytes");
  });
  bench("PQ · generatePqKeyPair (X-Wing, random)", async () => {
    await generatePqKeyPair();
  });
});

describe("identity wrap / unwrap a 32-byte key", () => {
  bench("classical · rsaEncrypt (RSA-4096)", async () => {
    await rsaEncrypt(rsaKeyPair.publicKey, fileKey);
  });
  bench("PQ · pqEncrypt", async () => {
    await pqEncrypt(pqKeyPair.publicKey, fileKey);
  });
  bench("classical · rsaDecrypt (RSA-4096)", async () => {
    await rsaDecrypt(rsaKeyPair.privateKey, toBytes(rsaCipher));
  });
  bench("PQ · pqDecrypt", async () => {
    await pqDecrypt(pqKeyPair.privateKey, pqCipher);
  });
});
