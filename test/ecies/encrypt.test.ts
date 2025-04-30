import { describe, it, expect } from "vitest";
import { generateKeyPair } from "../../src/ecies/keys";
import { encrypt } from "../../src/ecies/encrypt";
import { decrypt } from "../../src/ecies/decrypt";
import { randomBytes } from "@noble/hashes/utils";

describe("src/ecies/encrypt", () => {
  it("should encrypt a message that can be decrypted by the recipient", async () => {
    const { publicKey: recipientPublicKey, privateKey: recipientPrivateKey } =
      generateKeyPair();

    const originalMessage = randomBytes(128);

    const encryptedData = await encrypt(recipientPublicKey, originalMessage);

    expect(encryptedData).toBeDefined();
    expect(typeof encryptedData.ephemeralPublicKey).toBe("string");
    expect(typeof encryptedData.nonce).toBe("string");
    expect(typeof encryptedData.ciphertext).toBe("string");
    expect(typeof encryptedData.mac).toBe("string");

    const decryptedMessage = await decrypt(recipientPrivateKey, encryptedData);

    expect(decryptedMessage).toBeInstanceOf(Uint8Array);
    expect(decryptedMessage).toEqual(originalMessage);
  });

  it("should fail decryption if the wrong private key is used", async () => {
    const { publicKey: recipientPublicKey } = generateKeyPair();
    const { privateKey: wrongPrivateKey } = generateKeyPair();

    const originalMessage = new TextEncoder().encode(
      "Test message for wrong key"
    );

    const encryptedData = await encrypt(recipientPublicKey, originalMessage);

    const decryptedMessage = await decrypt(wrongPrivateKey, encryptedData);

    expect(decryptedMessage).toBeNull();
  });
});
