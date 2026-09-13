import { describe, expect, it, beforeEach } from "vitest";
import { generateKeyPair, type KeyPair } from "@/lib/trust/crypto";
import { publicKeyToDid } from "@/lib/trust/did";
import { issueCredential } from "@/lib/trust/credentials";
import { publishRevocationList } from "@/lib/trust/revocation";
import { evaluate, type PolicyConfig } from "@/lib/trust/policy";
import type { AttestationSubject, AuthorizationSubject, ActionReceiptSubject } from "@/lib/trust/types";

describe("policy.evaluate — coherent accept/refuse decisions", () => {
  let root: KeyPair;
  let rootDid: string;
  let agent: KeyPair;
  let agentDid: string;
  let config: PolicyConfig;

  beforeEach(() => {
    root = generateKeyPair();
    rootDid = publicKeyToDid(root.publicKey);
    agent = generateKeyPair();
    agentDid = publicKeyToDid(agent.publicKey);
    config = { trustedRootDids: [rootDid], reputationThreshold: 1000, minCleanReceipts: 2 };
  });

  it("accepts a well-scoped, validly-authorized, low-value request", () => {
    const auth = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, scope: { actions: ["book_travel"], maxAmount: 800, currency: "USD" } },
    });

    const result = evaluate({
      requesterDid: agentDid,
      credentials: [auth],
      revocationLists: [],
      task: { action: "book_travel", amount: 500, currency: "USD" },
      config,
    });

    expect(result.decision).toBe("ACCEPT");
    expect(result.matchedCredentialId).toBe(auth.id);
    expect(result.trace.map((t) => t.passed)).toEqual([true, true, true]);
  });

  it("refuses when no authorization credential is presented at all", () => {
    const result = evaluate({
      requesterDid: agentDid,
      credentials: [],
      revocationLists: [],
      task: { action: "book_travel", amount: 500, currency: "USD" },
      config,
    });
    expect(result.decision).toBe("REFUSE");
    expect(result.trace.at(-1)?.step).toBe("Authorization scope check");
  });

  it("gates high-value requests behind reputation evidence even with valid authorization", () => {
    const auth = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, scope: { actions: ["wire_transfer"], maxAmount: 100000, currency: "USD" } },
    });

    const withoutReputation = evaluate({
      requesterDid: agentDid,
      credentials: [auth],
      revocationLists: [],
      task: { action: "wire_transfer", amount: 5000, currency: "USD" },
      config,
    });
    expect(withoutReputation.decision).toBe("REFUSE");
    expect(withoutReputation.trace.some((t) => t.step.startsWith("Reputation check") && !t.passed)).toBe(true);

    const vouch = issueCredential<AttestationSubject>({
      type: "AttestationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, domain: "finance-ops", statement: "Handled 30+ transfers cleanly", strength: "high" },
    });

    const withReputation = evaluate({
      requesterDid: agentDid,
      credentials: [auth, vouch],
      revocationLists: [],
      task: { action: "wire_transfer", amount: 5000, currency: "USD" },
      config,
    });
    expect(withReputation.decision).toBe("ACCEPT");
  });

  it("a single disputed receipt blocks high-value acceptance even alongside a vouch", () => {
    const auth = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, scope: { actions: ["wire_transfer"], maxAmount: 100000, currency: "USD" } },
    });
    const vouch = issueCredential<AttestationSubject>({
      type: "AttestationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, domain: "finance-ops", statement: "Generally reliable", strength: "medium" },
    });
    const counterparty = generateKeyPair();
    const counterpartyDid = publicKeyToDid(counterparty.publicKey);
    const disputedReceipt = issueCredential<ActionReceiptSubject>({
      type: "ActionReceiptCredential",
      issuerDid: counterpartyDid,
      issuerKeyPair: counterparty,
      subject: {
        id: agentDid,
        taskId: "task-77",
        action: "wire_transfer",
        outcome: "disputed",
        counterpartyDid,
        summary: "Amount sent did not match invoice; under dispute.",
      },
    });

    const result = evaluate({
      requesterDid: agentDid,
      credentials: [auth, vouch, disputedReceipt],
      revocationLists: [],
      task: { action: "wire_transfer", amount: 5000, currency: "USD" },
      config,
    });

    expect(result.decision).toBe("REFUSE");
    expect(result.trace.some((t) => t.step.startsWith("Reputation check") && t.detail.includes("disputed"))).toBe(
      true
    );
  });

  it("accepts a high-value request backed by clean action history instead of a vouch", () => {
    const auth = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, scope: { actions: ["wire_transfer"], maxAmount: 100000, currency: "USD" } },
    });
    const counterpartyA = generateKeyPair();
    const counterpartyB = generateKeyPair();
    const receipts = [counterpartyA, counterpartyB].map((cp, i) =>
      issueCredential<ActionReceiptSubject>({
        type: "ActionReceiptCredential",
        issuerDid: publicKeyToDid(cp.publicKey),
        issuerKeyPair: cp,
        subject: {
          id: agentDid,
          taskId: `task-${i}`,
          action: "wire_transfer",
          outcome: "completed",
          counterpartyDid: publicKeyToDid(cp.publicKey),
          summary: "Completed without incident.",
        },
      })
    );

    const result = evaluate({
      requesterDid: agentDid,
      credentials: [auth, ...receipts],
      revocationLists: [],
      task: { action: "wire_transfer", amount: 5000, currency: "USD" },
      config,
    });
    expect(result.decision).toBe("ACCEPT");
  });
});

describe("policy.evaluate — attack scenarios (failure test)", () => {
  let root: KeyPair;
  let rootDid: string;
  let agent: KeyPair;
  let agentDid: string;
  let config: PolicyConfig;

  beforeEach(() => {
    root = generateKeyPair();
    rootDid = publicKeyToDid(root.publicKey);
    agent = generateKeyPair();
    agentDid = publicKeyToDid(agent.publicKey);
    config = { trustedRootDids: [rootDid], reputationThreshold: 1000, minCleanReceipts: 2 };
  });

  it("catches a forged credential: subject silently raised their own spending cap", () => {
    const legit = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, scope: { actions: ["book_travel"], maxAmount: 500, currency: "USD" } },
    });

    const forged = {
      ...legit,
      credentialSubject: {
        ...legit.credentialSubject,
        scope: { ...legit.credentialSubject.scope, maxAmount: 50000 },
      },
    };

    const result = evaluate({
      requesterDid: agentDid,
      credentials: [forged],
      revocationLists: [],
      task: { action: "book_travel", amount: 5000, currency: "USD" },
      config,
    });

    expect(result.decision).toBe("REFUSE");
    const verifyStep = result.trace.find((t) => t.step.startsWith("Credential verification"));
    expect(verifyStep?.passed).toBe(false);
    expect(verifyStep?.detail).toContain("signature invalid");
  });

  it("catches a revoked credential presented after the fact (e.g. offboarded contractor agent)", () => {
    const statusListId = "urn:uuid:acme-status-list";
    const auth = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, scope: { actions: ["book_travel"], maxAmount: 2000, currency: "USD" } },
      statusListId,
    });
    const revocationList = publishRevocationList(rootDid, root, statusListId, [auth.id]);

    const result = evaluate({
      requesterDid: agentDid,
      credentials: [auth],
      revocationLists: [revocationList],
      task: { action: "book_travel", amount: 500, currency: "USD" },
      config,
    });

    expect(result.decision).toBe("REFUSE");
    const verifyStep = result.trace.find((t) => t.step.startsWith("Credential verification"));
    expect(verifyStep?.detail).toContain("revoked");
  });

  it("catches a scope-exceeded request from an otherwise legitimate, unrevoked credential", () => {
    const auth = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, scope: { actions: ["book_travel"], maxAmount: 500, currency: "USD" } },
    });

    const result = evaluate({
      requesterDid: agentDid,
      credentials: [auth],
      revocationLists: [],
      task: { action: "book_travel", amount: 5000, currency: "USD" },
      config,
    });

    expect(result.decision).toBe("REFUSE");
    expect(result.trace.find((t) => t.step === "Authorization scope check")?.detail).toContain("Scope exceeded");
  });

  it("catches self-issued authority: an agent cannot grant itself permission", () => {
    const selfIssued = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: agentDid,
      issuerKeyPair: agent,
      subject: { id: agentDid, scope: { actions: ["wire_transfer"], maxAmount: 999999, currency: "USD" } },
    });

    const result = evaluate({
      requesterDid: agentDid,
      credentials: [selfIssued],
      revocationLists: [],
      task: { action: "wire_transfer", amount: 100, currency: "USD" },
      config,
    });

    expect(result.decision).toBe("REFUSE");
    expect(result.trace.find((t) => t.step === "Authorization scope check")?.detail).toContain(
      "not on the trusted-principal list"
    );
  });

  it("catches a credential replayed against a spoofed revocation list from an impostor issuer", () => {
    const statusListId = "urn:uuid:acme-status-list";
    const auth = issueCredential<AuthorizationSubject>({
      type: "AuthorizationCredential",
      issuerDid: rootDid,
      issuerKeyPair: root,
      subject: { id: agentDid, scope: { actions: ["book_travel"], maxAmount: 2000, currency: "USD" } },
      statusListId,
    });

    // Attacker publishes a "clean" list under root's DID but cannot sign as root.
    const impostor = generateKeyPair();
    const spoofedList = publishRevocationList(rootDid, impostor, statusListId, []);
    // Force the proof to (falsely) claim root as verificationMethod without root's key.
    const relabeled = { ...spoofedList, proof: { ...spoofedList.proof!, verificationMethod: rootDid } };

    const result = evaluate({
      requesterDid: agentDid,
      credentials: [auth],
      revocationLists: [relabeled],
      task: { action: "book_travel", amount: 500, currency: "USD" },
      config,
    });

    // The spoofed list fails signature verification, so status cannot be confirmed -> fail closed.
    expect(result.decision).toBe("REFUSE");
    const verifyStep = result.trace.find((t) => t.step.startsWith("Credential verification"));
    expect(verifyStep?.detail).toContain("revocation list");
  });
});
