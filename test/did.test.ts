import { describe, expect, it } from "vitest";
import { generateKeyPair } from "@/lib/trust/crypto";
import { didToPublicKey, publicKeyToDid, isValidDidKey } from "@/lib/trust/did";

describe("did:key", () => {
  it("round-trips a public key through DID encoding", () => {
    const { publicKey } = generateKeyPair();
    const did = publicKeyToDid(publicKey);
    expect(did.startsWith("did:key:z")).toBe(true);
    const recovered = didToPublicKey(did);
    expect(Array.from(recovered)).toEqual(Array.from(publicKey));
  });

  it("produces distinct DIDs for distinct keys", () => {
    const a = publicKeyToDid(generateKeyPair().publicKey);
    const b = publicKeyToDid(generateKeyPair().publicKey);
    expect(a).not.toEqual(b);
  });

  it("rejects malformed DIDs", () => {
    expect(isValidDidKey("did:key:znotbase58!!!")).toBe(false);
    expect(isValidDidKey("did:web:example.com")).toBe(false);
    expect(isValidDidKey("not-a-did")).toBe(false);
  });

  it("is self-certifying: no external state needed to resolve it", () => {
    const { publicKey } = generateKeyPair();
    const did = publicKeyToDid(publicKey);
    // Resolution is a pure function of the string itself.
    expect(Array.from(didToPublicKey(did))).toEqual(Array.from(publicKey));
  });
});
