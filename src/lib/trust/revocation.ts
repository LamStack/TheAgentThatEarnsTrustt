import { canonicalBytes } from "./canonical";
import { sign, verify, toHex, fromHex, type KeyPair } from "./crypto";
import { didToPublicKey } from "./did";
import type { Proof, RevocationList } from "./types";

/**
 * A minimal, signed status list (conceptually the same role as W3C
 * StatusList2021): the issuer periodically publishes a signed list of
 * revoked credential ids. Anyone who holds a credential from that issuer can
 * fetch the current list and check membership. Because the list itself is
 * signed, a verifier does not have to trust whoever is hosting/relaying it —
 * only the issuer's key.
 */
export function publishRevocationList(
  issuerDid: string,
  issuerKeyPair: KeyPair,
  id: string,
  revokedCredentialIds: string[],
  updated: Date = new Date()
): RevocationList {
  const unsigned: Omit<RevocationList, "proof"> = {
    id,
    issuer: issuerDid,
    updated: updated.toISOString(),
    revokedCredentialIds: [...revokedCredentialIds].sort(),
  };
  const signature = sign(canonicalBytes(unsigned), issuerKeyPair.secretKey);
  const proof: Proof = {
    type: "Ed25519Signature2020",
    created: updated.toISOString(),
    verificationMethod: issuerDid,
    proofValue: toHex(signature),
  };
  return { ...unsigned, proof };
}

export function verifyRevocationList(list: RevocationList): CredentialCheckLike {
  if (!list.proof) return { valid: false, reasons: ["revocation list missing proof"] };
  if (list.proof.verificationMethod !== list.issuer) {
    return { valid: false, reasons: ["revocation list proof does not match issuer"] };
  }
  let issuerPublicKey: Uint8Array;
  try {
    issuerPublicKey = didToPublicKey(list.issuer);
  } catch (err) {
    return { valid: false, reasons: [`cannot resolve status list issuer DID: ${(err as Error).message}`] };
  }
  const { proof, ...unsigned } = list;
  const ok = verify(fromHex(proof.proofValue), canonicalBytes(unsigned), issuerPublicKey);
  return ok ? { valid: true, reasons: [] } : { valid: false, reasons: ["status list signature invalid"] };
}

export function isRevoked(list: RevocationList, credentialId: string): boolean {
  return list.revokedCredentialIds.includes(credentialId);
}

interface CredentialCheckLike {
  valid: boolean;
  reasons: string[];
}
