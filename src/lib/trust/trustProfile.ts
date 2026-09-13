import { verifyCredential } from "./credentials";
import { isRevoked, verifyRevocationList } from "./revocation";
import type {
  ActionReceiptSubject,
  AttestationSubject,
  AuthorizationSubject,
  RevocationList,
  VerifiableCredential,
} from "./types";

export interface CredentialEntry {
  credential: VerifiableCredential;
  valid: boolean;
  revoked: boolean;
  reasons: string[];
}

export interface TrustProfile {
  did: string;
  computedAt: string;
  credentials: CredentialEntry[];
  authorizations: { issuer: string; trusted: boolean; scopeSummary: string; valid: boolean }[];
  vouches: { issuer: string; domain: string; strength: AttestationSubject["strength"]; valid: boolean }[];
  history: { completed: number; failed: number; disputed: number };
  /**
   * A short, rule-derived label — NOT a numeric score. Always paired with
   * the rule that produced it so it stays auditable.
   */
  standing: { label: "Unestablished" | "Provisional" | "Established"; rule: string };
}

export function buildTrustProfile(
  did: string,
  credentials: VerifiableCredential[],
  revocationLists: RevocationList[],
  trustedRootDids: string[],
  now: Date = new Date()
): TrustProfile {
  const entries: CredentialEntry[] = credentials
    .filter((vc) => vc.credentialSubject.id === did)
    .map((vc) => {
      const sigCheck = verifyCredential(vc, now);
      let revoked = false;
      const reasons = [...sigCheck.reasons];
      if (sigCheck.valid && vc.credentialStatus) {
        const list = revocationLists.find(
          (l) => l.issuer === vc.issuer && l.id === vc.credentialStatus!.id
        );
        if (list && verifyRevocationList(list).valid && isRevoked(list, vc.id)) {
          revoked = true;
          reasons.push(`revoked on ${list.updated}`);
        }
      }
      return { credential: vc, valid: sigCheck.valid && !revoked, revoked, reasons };
    });

  const authorizations = entries
    .filter((e) => e.credential.type[1] === "AuthorizationCredential")
    .map((e) => {
      const subject = e.credential.credentialSubject as AuthorizationSubject;
      return {
        issuer: e.credential.issuer,
        trusted: trustedRootDids.includes(e.credential.issuer),
        scopeSummary: `${subject.scope.actions.join(", ")}${
          subject.scope.maxAmount ? ` up to ${subject.scope.maxAmount} ${subject.scope.currency ?? ""}` : ""
        }`,
        valid: e.valid,
      };
    });

  const vouches = entries
    .filter((e) => e.credential.type[1] === "AttestationCredential")
    .map((e) => {
      const subject = e.credential.credentialSubject as AttestationSubject;
      return { issuer: e.credential.issuer, domain: subject.domain, strength: subject.strength, valid: e.valid };
    });

  const receipts = entries.filter((e) => e.credential.type[1] === "ActionReceiptCredential" && e.valid);
  const history = {
    completed: receipts.filter((e) => (e.credential.credentialSubject as ActionReceiptSubject).outcome === "completed").length,
    failed: receipts.filter((e) => (e.credential.credentialSubject as ActionReceiptSubject).outcome === "failed").length,
    disputed: receipts.filter((e) => (e.credential.credentialSubject as ActionReceiptSubject).outcome === "disputed").length,
  };

  let standing: TrustProfile["standing"];
  const hasTrustedAuth = authorizations.some((a) => a.trusted && a.valid);
  if (history.disputed > 0) {
    standing = {
      label: "Unestablished",
      rule: "Any unresolved disputed action receipt forces Unestablished, regardless of other credentials.",
    };
  } else if (hasTrustedAuth && (history.completed >= 2 || vouches.some((v) => v.valid && v.strength !== "low"))) {
    standing = {
      label: "Established",
      rule: "Has a valid authorization from a trusted principal, and either 2+ completed receipts or a medium/high-strength vouch.",
    };
  } else if (hasTrustedAuth) {
    standing = {
      label: "Provisional",
      rule: "Has a valid authorization from a trusted principal, but not yet enough history or vouches for Established.",
    };
  } else {
    standing = {
      label: "Unestablished",
      rule: "No valid authorization credential from a trusted principal was found.",
    };
  }

  return {
    did,
    computedAt: now.toISOString(),
    credentials: entries,
    authorizations,
    vouches,
    history,
    standing,
  };
}
