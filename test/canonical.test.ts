import { describe, expect, it } from "vitest";
import { canonicalize } from "@/lib/trust/canonical";

describe("canonicalize", () => {
  it("produces identical output regardless of key order", () => {
    const a = { b: 1, a: 2, c: { y: 1, x: 2 } };
    const b = { a: 2, c: { x: 2, y: 1 }, b: 1 };
    expect(canonicalize(a)).toEqual(canonicalize(b));
  });

  it("preserves array order", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  it("omits undefined-valued keys but keeps null", () => {
    expect(canonicalize({ a: undefined, b: null })).toBe('{"b":null}');
  });

  it("changes output when any nested value changes (tamper detection)", () => {
    const original = { credentialSubject: { scope: { maxAmount: 500 } } };
    const tampered = { credentialSubject: { scope: { maxAmount: 50000 } } };
    expect(canonicalize(original)).not.toEqual(canonicalize(tampered));
  });
});
