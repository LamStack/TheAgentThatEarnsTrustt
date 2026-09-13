import { generateKeyPair, publicKeyToDid, issueCredential, publishRevocationList } from "@/lib/trust";
import type {
  ActionReceiptSubject,
  AttestationSubject,
  AuthorizationSubject,
  PolicyConfig,
  RevocationList,
  TaskRequest,
  VerifiableCredential,
} from "@/lib/trust";

/**
 * A self-contained demo "world": one human/company principal (Aurora
 * Logistics) plus several agents it deals with. Everything here is
 * generated fresh per server instance and is fully self-consistent —
 * every signature in this file is real (Ed25519, verified the same way the
 * policy engine verifies any other credential). Nothing is mocked.
 */

const aurora = generateKeyPair();
const auroraDid = publicKeyToDid(aurora.publicKey);

const atlas = generateKeyPair();
const atlasDid = publicKeyToDid(atlas.publicKey);

const nova = generateKeyPair();
const novaDid = publicKeyToDid(nova.publicKey);

const skybook = generateKeyPair();
const skybookDid = publicKeyToDid(skybook.publicKey);

const pastVendorA = generateKeyPair();
const pastVendorB = generateKeyPair();

export const config: PolicyConfig = {
  trustedRootDids: [auroraDid],
  reputationThreshold: 1000,
  minCleanReceipts: 2,
};

const STATUS_LIST_ID = "urn:uuid:aurora-status-list-2026";

// Atlas: procurement agent, currently authorized for domestic travel up to $800.
const atlasAuth = issueCredential<AuthorizationSubject>({
  type: "AuthorizationCredential",
  issuerDid: auroraDid,
  issuerKeyPair: aurora,
  subject: {
    id: atlasDid,
    scope: { actions: ["book_travel"], maxAmount: 800, currency: "USD", resources: ["domestic"] },
  },
  issuanceDate: new Date("2026-06-01"),
  expirationDate: new Date("2027-06-01"),
  statusListId: STATUS_LIST_ID,
});

const atlasVouch = issueCredential<AttestationSubject>({
  type: "AttestationCredential",
  issuerDid: auroraDid,
  issuerKeyPair: aurora,
  subject: {
    id: atlasDid,
    domain: "travel-booking",
    statement: "Onboarded procurement agent, reviewed by Aurora Logistics ops team.",
    strength: "medium",
  },
  issuanceDate: new Date("2026-06-01"),
});

const atlasReceipt1 = issueCredential<ActionReceiptSubject>({
  type: "ActionReceiptCredential",
  issuerDid: publicKeyToDid(pastVendorA.publicKey),
  issuerKeyPair: pastVendorA,
  subject: {
    id: atlasDid,
    taskId: "task-2026-0031",
    action: "book_travel",
    outcome: "completed",
    counterpartyDid: publicKeyToDid(pastVendorA.publicKey),
    summary: "Domestic flight booked and paid within authorized scope.",
  },
  issuanceDate: new Date("2026-07-10"),
});

const atlasReceipt2 = issueCredential<ActionReceiptSubject>({
  type: "ActionReceiptCredential",
  issuerDid: publicKeyToDid(pastVendorB.publicKey),
  issuerKeyPair: pastVendorB,
  subject: {
    id: atlasDid,
    taskId: "task-2026-0044",
    action: "book_travel",
    outcome: "completed",
    counterpartyDid: publicKeyToDid(pastVendorB.publicKey),
    summary: "Domestic flight booked and paid within authorized scope.",
  },
  issuanceDate: new Date("2026-08-02"),
});

// A second, separately-issued credential for Atlas that Aurora has since revoked
// (simulating an incident: this specific grant was pulled after a policy review).
const atlasRevokedAuth = issueCredential<AuthorizationSubject>({
  type: "AuthorizationCredential",
  issuerDid: auroraDid,
  issuerKeyPair: aurora,
  subject: {
    id: atlasDid,
    scope: { actions: ["book_travel"], maxAmount: 800, currency: "USD", resources: ["domestic", "international"] },
  },
  issuanceDate: new Date("2026-01-01"),
  expirationDate: new Date("2027-01-01"),
  statusListId: STATUS_LIST_ID,
});

// Nova: finance-ops agent, authorized for large wire transfers but brand new (no history yet).
const novaAuth = issueCredential<AuthorizationSubject>({
  type: "AuthorizationCredential",
  issuerDid: auroraDid,
  issuerKeyPair: aurora,
  subject: {
    id: novaDid,
    scope: { actions: ["wire_transfer"], maxAmount: 100000, currency: "USD" },
  },
  issuanceDate: new Date("2026-09-01"),
  expirationDate: new Date("2027-09-01"),
  statusListId: STATUS_LIST_ID,
});

const novaVouch = issueCredential<AttestationSubject>({
  type: "AttestationCredential",
  issuerDid: auroraDid,
  issuerKeyPair: aurora,
  subject: {
    id: novaDid,
    domain: "finance-ops",
    statement: "Reviewed and approved for treasury operations by Aurora Logistics finance team.",
    strength: "high",
  },
  issuanceDate: new Date("2026-09-01"),
});

// Aurora's live, signed status list. Only atlasRevokedAuth is revoked.
export const auroraRevocationList: RevocationList = publishRevocationList(
  auroraDid,
  aurora,
  STATUS_LIST_ID,
  [atlasRevokedAuth.id],
  new Date("2026-09-05")
);

export interface DemoScenario {
  id: string;
  title: string;
  narrative: string;
  requesterDid: string;
  requesterLabel: string;
  verifierLabel: string;
  credentials: VerifiableCredential[];
  revocationLists: RevocationList[];
  task: TaskRequest;
  expected: "ACCEPT" | "REFUSE";
  attack: boolean;
  attackDescription?: string;
}

function tamperCredential(vc: VerifiableCredential<AuthorizationSubject>): VerifiableCredential<AuthorizationSubject> {
  return {
    ...vc,
    credentialSubject: {
      ...vc.credentialSubject,
      scope: { ...vc.credentialSubject.scope, maxAmount: 50000 },
    },
  };
}

export function getScenarios(): DemoScenario[] {
  return [
    {
      id: "legit-booking",
      title: "Legitimate request within scope",
      narrative:
        "Atlas, Aurora Logistics' procurement agent, asks SkyBook (a travel-booking agent) to book a $650 domestic flight.",
      requesterDid: atlasDid,
      requesterLabel: "Atlas (procurement agent)",
      verifierLabel: "SkyBook (travel vendor agent)",
      credentials: [atlasAuth, atlasVouch, atlasReceipt1, atlasReceipt2],
      revocationLists: [auroraRevocationList],
      task: { action: "book_travel", amount: 650, currency: "USD", resource: "domestic" },
      expected: "ACCEPT",
      attack: false,
    },
    {
      id: "forged-credential",
      title: "Attack: forged authorization",
      narrative:
        "“Mallory” copies Atlas's real authorization credential and edits the spending cap from $800 to $50,000 — without Aurora's private key, so she cannot produce a matching signature.",
      requesterDid: atlasDid,
      requesterLabel: "Mallory (posing as Atlas)",
      verifierLabel: "SkyBook (travel vendor agent)",
      credentials: [tamperCredential(atlasAuth)],
      revocationLists: [auroraRevocationList],
      task: { action: "book_travel", amount: 42000, currency: "USD", resource: "domestic" },
      expected: "REFUSE",
      attack: true,
      attackDescription:
        "Signature verification recomputes the canonical bytes of the credential and checks them against Aurora's public key. Any edit to the payload invalidates the signature.",
    },
    {
      id: "revoked-credential",
      title: "Attack: replaying a revoked credential",
      narrative:
        "An old Atlas credential — valid on its face, correctly signed by Aurora — is replayed after Aurora revoked it during a security review.",
      requesterDid: atlasDid,
      requesterLabel: "Atlas (using a revoked grant)",
      verifierLabel: "SkyBook (travel vendor agent)",
      credentials: [atlasRevokedAuth],
      revocationLists: [auroraRevocationList],
      task: { action: "book_travel", amount: 500, currency: "USD", resource: "international" },
      expected: "REFUSE",
      attack: true,
      attackDescription:
        "The credential's signature is valid, but Aurora's current, independently-signed status list marks this credential id as revoked. Verification checks revocation as a distinct step from signature validity.",
    },
    {
      id: "scope-exceeded",
      title: "Policy refusal: scope exceeded",
      narrative:
        "Atlas presents his real, current, unrevoked credential — but asks SkyBook to book a $4,800 flight, well above his $800 authorization.",
      requesterDid: atlasDid,
      requesterLabel: "Atlas (procurement agent)",
      verifierLabel: "SkyBook (travel vendor agent)",
      credentials: [atlasAuth, atlasVouch, atlasReceipt1, atlasReceipt2],
      revocationLists: [auroraRevocationList],
      task: { action: "book_travel", amount: 4800, currency: "USD", resource: "domestic" },
      expected: "REFUSE",
      attack: false,
      attackDescription:
        "Not a forgery or a spoof — every credential here is genuine and unrevoked. The request simply falls outside the scope Aurora granted, so policy (not cryptography) is what refuses it.",
    },
    {
      id: "reputation-gate",
      title: "High-value transfer without reputation evidence",
      narrative:
        "Nova, a brand-new finance-ops agent, is validly authorized for wire transfers up to $100,000 — but has no track record yet. She requests a $25,000 transfer.",
      requesterDid: novaDid,
      requesterLabel: "Nova (finance-ops agent)",
      verifierLabel: "Ledger (payments vendor agent)",
      credentials: [novaAuth],
      revocationLists: [auroraRevocationList],
      task: { action: "wire_transfer", amount: 25000, currency: "USD" },
      expected: "REFUSE",
      attack: false,
      attackDescription:
        "Authorization alone is enough for low-stakes actions, but above the $1,000 reputation threshold the policy also requires a trusted vouch or a track record of clean completed receipts. Nova has neither yet.",
    },
    {
      id: "reputation-gate-cleared",
      title: "Same request, with a trusted vouch",
      narrative:
        "Same request from Nova — but this time Aurora's finance team has countersigned a vouch for her after a manual review.",
      requesterDid: novaDid,
      requesterLabel: "Nova (finance-ops agent)",
      verifierLabel: "Ledger (payments vendor agent)",
      credentials: [novaAuth, novaVouch],
      revocationLists: [auroraRevocationList],
      task: { action: "wire_transfer", amount: 25000, currency: "USD" },
      expected: "ACCEPT",
      attack: false,
    },
  ];
}

export function getWorldSummary() {
  return {
    principals: [{ did: auroraDid, label: "Aurora Logistics (root principal)" }],
    agents: [
      { did: atlasDid, label: "Atlas (procurement agent)" },
      { did: novaDid, label: "Nova (finance-ops agent)" },
      { did: skybookDid, label: "SkyBook (travel vendor agent)" },
    ],
    config,
  };
}
