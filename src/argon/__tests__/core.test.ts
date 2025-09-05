import { describe, it, expect } from "vitest";
import { getArgon2idHash } from "../core";

describe("getArgon2idHash", () => {
  const testPassword = "testPassword123";
  const testSalt = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  ]);

  it("should return Uint8Array when no encoding format specified", async () => {
    const result = await getArgon2idHash(testPassword, testSalt);

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it("should return base64 encoded string when format is base64", async () => {
    const result = await getArgon2idHash(testPassword, testSalt, "base64");

    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
    expect(() => atob(result)).not.toThrow();
  });

  it("should use custom options when provided", async () => {
    const customOpts = {
      t: 1,
      m: 64,
      p: 1,
      dkLen: 16,
    };

    const result = await getArgon2idHash(
      testPassword,
      testSalt,
      "bytes",
      customOpts
    );

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(16);
  });

  it("should always return same output for same input", async () => {
    const password =
      "0xe02aceabcee1e0a6e0ce73ca4f4eeaf0cbeec634341de8c76d7506029d97c18925a1c0fc36a03d89a6a54608d7569200528158806d272acfd3e26c2c54cb772e1b";
    const salt = new Uint8Array([
      190, 19, 179, 140, 150, 220, 178, 240, 159, 187, 157, 62, 151, 58, 56, 63,
      56, 176, 23, 201, 221, 191, 213, 25,
    ]);
    const exptectedHash = "MYCcEkYs+uilj6j+k56zFAsI4oxOjWPRc9whzB25hJU=";

    const startTime = performance.now();
    const hash = await getArgon2idHash(password, salt, "base64");
    const endTime = performance.now();
    console.log(`Argon2id hash took ${endTime - startTime}ms`);
    expect(hash).toBe(exptectedHash);
  });
});
