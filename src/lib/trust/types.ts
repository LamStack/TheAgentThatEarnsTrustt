/** Shared types for the trust engine: identity, claims, verification, policy. */

export interface Proof {
  type: "Ed25519Signature2020";
  created: string; // ISO-8601
  verificationMethod: string; // DID that produced the signature
  proofValue: string; // hex-encoded signature over the canonicalized, proof-less document
}

export type CredentialType = "AuthorizationCredential" | "AttestationCredential" | "ActionReceiptCredential";

export interface AuthorizationScope {
  /** Action types this grant authorizes, e.g. "book_travel", "wire_transfer". */
  actions: string[];
  /** Optional ceiling on a monetary action. Absence means no monetary action is covered. */
  maxAmount?: number;
  currency?: string;
  /** Optional resource/domain restriction, e.g. ["travel.acme-corp.com"]. */
  resources?: string[];
  /** Whether the subject may re-delegate a narrower version of this scope to another agent. */
  delegable?: boolean;
}

export interface AuthorizationSubject {
  id: string; // subject DID (the agent being granted authority)
  scope: AuthorizationScope;
}

export interface AttestationSubject {
  id: string; // subject DID being vouched for
  domain: string; // e.g. "travel-booking", "code-review"
  statement: string; // human-readable claim, e.g. "Completed 40+ bookings without incident"
  strength: "low" | "medium" | "high"; // categorical confidence, chosen by the issuer - not a numeric score
}

export interface ActionReceiptSubject {
  id: string; // subject DID (the agent who performed the task)
  taskId: string;
  action: string;
  outcome: "completed" | "failed" | "disputed";
  counterpartyDid: string; // who the task was performed for/with
  summary: string;
}

export type CredentialSubject = AuthorizationSubject | AttestationSubject | ActionReceiptSubject;

export interface CredentialStatusRef {
  id: string; // revocation list id
  type: "TrustRegistryStatusList2024";
  statusListIssuer: string; // DID of the list publisher (must equal credential issuer)
}

export interface VerifiableCredential<S extends CredentialSubject = CredentialSubject> {
  "@context": string[];
  id: string;
  type: ["VerifiableCredential", CredentialType];
  issuer: string; // DID
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: S;
  credentialStatus?: CredentialStatusRef;
  proof?: Proof;
}

export interface RevocationList {
  id: string;
  issuer: string; // DID, must match the credential issuer it governs
  updated: string;
  revokedCredentialIds: string[];
  proof?: Proof;
}

export interface TaskRequest {
  action: string;
  amount?: number;
  currency?: string;
  resource?: string;
}

export interface PolicyStep {
  step: string;
  passed: boolean;
  detail: string;
}

export interface PolicyResult {
  decision: "ACCEPT" | "REFUSE";
  trace: PolicyStep[];
  matchedCredentialId?: string;
}
