import { describe, expect, it } from "vitest";
import { base58Decode, base58Encode } from "@/lib/trust/base58";

describe("base58", () => {
  it("round-trips random byte sequences", () => {
    for (let i = 0; i < 50; i++) {
      const bytes = crypto.getRandomValues(new Uint8Array(1 + (i % 40)));
      const encoded = base58Encode(bytes);
      const decoded = base58Decode(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(bytes));
    }
  });

  it("preserves leading zero bytes", () => {
    const bytes = new Uint8Array([0, 0, 1, 2, 3]);
    const encoded = base58Encode(bytes);
    expect(encoded.startsWith("11")).toBe(true);
    expect(Array.from(base58Decode(encoded))).toEqual(Array.from(bytes));
  });

  it("matches a known test vector", () => {
    const bytes = new TextEncoder().encode("Hello World");
    expect(base58Encode(bytes)).toBe("JxF12TrwUP45BMd");
  });
});
