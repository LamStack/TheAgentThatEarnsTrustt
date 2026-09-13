import { describe, expect, it } from "vitest";
import { generateKeyPair } from "@/lib/trust/crypto";
import { publicKeyToDid } from "@/lib/trust/did";
import { issueCredential, verifyCredential } from "@/lib/trust/credentials";
import type { AuthorizationSubject, VerifiableCredential } from "@/lib/trust/types";

function makeIssuerAndSubject() {
  const issuerKeyPair = generateKeyPair();
  const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
  const subjectKeyPair = generateKeyPair();
  const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
  return { issuerKeyPair, issuerDid, subjectKeyPair, subjectDid };
}

describe("issueCredential / verifyCredential", () => {
  it("issues a credential that verifies successfully", () => {
    const { issuerKeyPair, issuerDid, subjectDid } = makeIssuerAndSubject();
    const vc = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid,
      issuerKeyPair,
      subject: { id: subjectDid, scope: { actions: ["book_travel"], maxAmount: 500, currency: "USD" } },
    });
    const result = verifyCredential(vc);
    expect(result.valid).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it("rejects a credential whose subject data was tampered with after issuance", () => {
    const { issuerKeyPair, issuerDid, subjectDid } = makeIssuerAndSubject();
    const vc = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid,
      issuerKeyPair,
      subject: { id: subjectDid, scope: { actions: ["book_travel"], maxAmount: 500, currency: "USD" } },
    });

    // Attacker bumps their own spending limit by 100x without the issuer's key.
    const tampered: VerifiableCredential<AuthorizationSubject> = {
      ...vc,
      credentialSubject: { ...vc.credentialSubject, scope: { ...vc.credentialSubject.scope, maxAmount: 50000 } },
    };

    const result = verifyCredential(tampered);
    expect(result.valid).toBe(false);
    expect(result.reasons.some((r) => r.includes("signature invalid"))).toBe(true);
  });

  it("rejects a credential signed by a different key than it claims", () => {
    const { issuerKeyPair, subjectDid } = makeIssuerAndSubject();
    const impostorKeyPair = generateKeyPair();
    const impostorDid = publicKeyToDid(impostorKeyPair.publicKey);
    const realIssuerDid = publicKeyToDid(issuerKeyPair.publicKey);

    const vc = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: realIssuerDid,
      issuerKeyPair,
      subject: { id: subjectDid, scope: { actions: ["book_travel"], maxAmount: 500 } },
    });

    // Forger claims a different, unrelated issuer DID for the same signature.
    const spoofed: VerifiableCredential<AuthorizationSubject> = {
      ...vc,
      issuer: impostorDid,
      proof: { ...vc.proof!, verificationMethod: impostorDid },
    };

    const result = verifyCredential(spoofed);
    expect(result.valid).toBe(false);
  });

  it("rejects an expired credential", () => {
    const { issuerKeyPair, issuerDid, subjectDid } = makeIssuerAndSubject();
    const vc = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid,
      issuerKeyPair,
      subject: { id: subjectDid, scope: { actions: ["book_travel"], maxAmount: 500 } },
      issuanceDate: new Date("2020-01-01"),
      expirationDate: new Date("2020-06-01"),
    });
    const result = verifyCredential(vc, new Date("2024-01-01"));
    expect(result.valid).toBe(false);
    expect(result.reasons.some((r) => r.includes("expired"))).toBe(true);
  });

  it("accepts a credential before its expiration date", () => {
    const { issuerKeyPair, issuerDid, subjectDid } = makeIssuerAndSubject();
    const vc = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid,
      issuerKeyPair,
      subject: { id: subjectDid, scope: { actions: ["book_travel"], maxAmount: 500 } },
      issuanceDate: new Date("2024-01-01"),
      expirationDate: new Date("2025-01-01"),
    });
    const result = verifyCredential(vc, new Date("2024-06-01"));
    expect(result.valid).toBe(true);
  });
});
