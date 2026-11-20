import { describe, it, expect } from "vitest";
import { XWing } from "@hpke/hybridkem-x-wing";
import { generatePqKeyPair, getPublicKey } from "../keys";
import { pqEncrypt, pqDecrypt } from "../core";
import { bytesToBase64 } from "../../utils";
import { X_WING_VECTORS } from "./x-wing-vectors";

const hexToBytes = (hex: string) =>
  Uint8Array.from(hex.match(/../g)!.map((byte) => parseInt(byte, 16)));

describe("PQ Known-Answer Tests (official X-Wing vectors)", () => {
  const kem = new XWing();

  X_WING_VECTORS.forEach((vector, index) => {
    describe(`vector ${index}`, () => {
      const seed = hexToBytes(vector.seed);
      const sk = hexToBytes(vector.sk);
      const pk = hexToBytes(vector.pk);
      const ct = hexToBytes(vector.ct);
      const ss = hexToBytes(vector.ss);

      it("generatePqKeyPair(seed) matches the official key pair", async () => {
        const keyPair = await generatePqKeyPair(seed);

        // X-Wing's private key is the seed itself.
        expect(keyPair.privateKey).toEqual(sk);
        expect(keyPair.publicKey).toEqual(pk);
      });

      it("getPublicKey(seed) matches the official public key", async () => {
        const publicKey = await getPublicKey(seed);
        expect(publicKey).toEqual(pk);
      });

      it("base64 key pair matches the official key bytes", async () => {
        const keyPair = await generatePqKeyPair(seed, "base64");

        expect(keyPair.publicKey).toBe(bytesToBase64(pk));
        expect(keyPair.privateKey).toBe(bytesToBase64(sk));
      });

      it("decapsulation matches the official shared secret", async () => {
        const recipientKey = await kem.deserializePrivateKey(sk);
        const sharedSecret = new Uint8Array(
          await kem.decap({ recipientKey, enc: ct })
        );

        expect(sharedSecret).toEqual(ss);
      });

      it("deterministic encapsulation matches the official ciphertext and shared secret", async () => {
        const eseed = hexToBytes(vector.eseed);
        const recipientPublicKey = await kem.deserializePublicKey(pk);

        const { enc, sharedSecret } = await kem.encap({
          recipientPublicKey,
          ekm: eseed, // official vector relation: encapsulate(pk, eseed) -> (ct, ss)
        });

        expect(new Uint8Array(enc)).toEqual(ct);
        expect(new Uint8Array(sharedSecret)).toEqual(ss);
      });

      it("the module round-trips on the official key pair", async () => {
        const message = new TextEncoder().encode(`vector-${index}-roundtrip`);

        const encrypted = await pqEncrypt(pk, message);
        const decrypted = await pqDecrypt(sk, encrypted);

        expect(new Uint8Array(decrypted)).toEqual(message);
      });
    });
  });
});
