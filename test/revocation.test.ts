import { describe, expect, it } from "vitest";
import { generateKeyPair } from "@/lib/trust/crypto";
import { publicKeyToDid } from "@/lib/trust/did";
import { publishRevocationList, verifyRevocationList, isRevoked } from "@/lib/trust/revocation";

describe("revocation list", () => {
  it("verifies a properly signed list", () => {
    const kp = generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const list = publishRevocationList(did, kp, "urn:uuid:list-1", ["urn:uuid:cred-1"]);
    expect(verifyRevocationList(list).valid).toBe(true);
    expect(isRevoked(list, "urn:uuid:cred-1")).toBe(true);
    expect(isRevoked(list, "urn:uuid:cred-2")).toBe(false);
  });

  it("rejects a list tampered with after signing (e.g. entry quietly removed)", () => {
    const kp = generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const list = publishRevocationList(did, kp, "urn:uuid:list-1", ["urn:uuid:cred-1", "urn:uuid:cred-2"]);

    const tampered = { ...list, revokedCredentialIds: ["urn:uuid:cred-2"] };
    expect(verifyRevocationList(tampered).valid).toBe(false);
  });

  it("rejects a list signed by someone other than the claimed issuer", () => {
    const kp = generateKeyPair();
    const impostor = generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const impostorDid = publicKeyToDid(impostor.publicKey);

    const list = publishRevocationList(did, kp, "urn:uuid:list-1", ["urn:uuid:cred-1"]);
    const relabeled = { ...list, issuer: impostorDid, proof: { ...list.proof!, verificationMethod: impostorDid } };
    expect(verifyRevocationList(relabeled).valid).toBe(false);
  });
});
