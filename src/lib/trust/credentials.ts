import { canonicalBytes } from "./canonical";
import { sign, verify, toHex, fromHex, type KeyPair } from "./crypto";
import { didToPublicKey } from "./did";
import type {
  Proof,
  CredentialType,
  CredentialSubject,
  VerifiableCredential,
} from "./types";

const CONTEXT = ["https://www.w3.org/ns/credentials/v2", "https://trust-layer.example/contexts/v1"];

export interface IssueCredentialParams<S extends CredentialSubject> {
  id?: string;
  type: CredentialType;
  issuerDid: string;
  issuerKeyPair: KeyPair;
  subject: S;
  issuanceDate?: Date;
  expirationDate?: Date;
  /** If set, ties this credential to a revocation list published by the issuer. */
  statusListId?: string;
}

/** Issuer signs the credential: canonicalize everything except `proof`, then sign the bytes. */
export function issueCredential<S extends CredentialSubject>(
  params: IssueCredentialParams<S>
): VerifiableCredential<S> {
  const unsigned: Omit<VerifiableCredential<S>, "proof"> = {
    "@context": CONTEXT,
    id: params.id ?? `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential", params.type],
    issuer: params.issuerDid,
    issuanceDate: (params.issuanceDate ?? new Date()).toISOString(),
    ...(params.expirationDate ? { expirationDate: params.expirationDate.toISOString() } : {}),
    credentialSubject: params.subject,
    ...(params.statusListId
      ? {
          credentialStatus: {
            id: params.statusListId,
            type: "TrustRegistryStatusList2024" as const,
            statusListIssuer: params.issuerDid,
          },
        }
      : {}),
  };

  const signature = sign(canonicalBytes(unsigned), params.issuerKeyPair.secretKey);
  const proof: Proof = {
    type: "Ed25519Signature2020",
    created: new Date().toISOString(),
    verificationMethod: params.issuerDid,
    proofValue: toHex(signature),
  };

  return { ...unsigned, proof };
}

export interface CredentialCheck {
  valid: boolean;
  reasons: string[];
}

/**
 * Verifies a credential end to end:
 *  1. structural sanity (proof present, issuer matches verificationMethod)
 *  2. signature verification against the issuer's did:key-derived public key
 *  3. temporal validity (issuanceDate not in the future, not expired)
 *
 * Revocation is intentionally NOT checked here — that requires the issuer's
 * current status list, which the policy engine checks separately (see
 * revocation.ts + policy.ts) so that "signature valid" and "not revoked" stay
 * two distinct, individually explainable facts.
 */
export function verifyCredential(vc: VerifiableCredential, now: Date = new Date()): CredentialCheck {
  const reasons: string[] = [];

  if (!vc.proof) {
    return { valid: false, reasons: ["missing proof"] };
  }
  if (vc.proof.verificationMethod !== vc.issuer) {
    return { valid: false, reasons: ["proof.verificationMethod does not match issuer"] };
  }

  let issuerPublicKey: Uint8Array;
  try {
    issuerPublicKey = didToPublicKey(vc.issuer);
  } catch (err) {
    return { valid: false, reasons: [`cannot resolve issuer DID: ${(err as Error).message}`] };
  }

  const { proof, ...unsigned } = vc;
  const signatureValid = verify(fromHex(proof.proofValue), canonicalBytes(unsigned), issuerPublicKey);
  if (!signatureValid) {
    reasons.push("signature invalid: credential content does not match issuer's signature");
  }

  const issuance = new Date(vc.issuanceDate);
  if (issuance.getTime() > now.getTime()) {
    reasons.push("issuanceDate is in the future");
  }

  if (vc.expirationDate) {
    const expiry = new Date(vc.expirationDate);
    if (expiry.getTime() <= now.getTime()) {
      reasons.push(`credential expired on ${vc.expirationDate}`);
    }
  }

  return { valid: reasons.length === 0, reasons };
}
