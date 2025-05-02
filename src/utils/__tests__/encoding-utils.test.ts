import { describe, it, expect } from "vitest";
import { toBytes, bytesToBase64, encodeData } from "../encoding-utils";

describe("Encoding Utilities", () => {
  describe("encodeData", () => {
    it("should return the original Uint8Array when encoding is 'bytes'", () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const result = encodeData(data, "bytes");

      expect(result instanceof Uint8Array).toBe(true);
      expect(result).toBe(data); // Should be the same reference
    });

    it("should return base64 string when encoding is 'base64'", () => {
      const data = new TextEncoder().encode("Test Data");
      const result = encodeData(data, "base64");

      expect(typeof result).toBe("string");
      expect(result).toBe(bytesToBase64(data));
    });

    it("should handle empty arrays", () => {
      const emptyArray = new Uint8Array(0);

      const bytesResult = encodeData(emptyArray, "bytes");
      expect(bytesResult instanceof Uint8Array).toBe(true);
      expect(bytesResult.length).toBe(0);

      const base64Result = encodeData(emptyArray, "base64");
      expect(base64Result).toBe("");
    });

    it("should maintain roundtrip integrity", () => {
      const original = new TextEncoder().encode("Testing roundtrip conversion");

      const base64 = encodeData(original, "base64");
      const backToBytes = toBytes(base64 as string);

      expect(backToBytes.length).toBe(original.length);

      for (let i = 0; i < original.length; i++) {
        expect(backToBytes[i]).toBe(original[i]);
      }
    });
  });
});
