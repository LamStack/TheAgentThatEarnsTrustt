import { verifyCredential } from "./credentials";
import { isRevoked, verifyRevocationList } from "./revocation";
import { isValidDidKey } from "./did";
import type {
  AuthorizationSubject,
  AttestationSubject,
  ActionReceiptSubject,
  PolicyResult,
  PolicyStep,
  RevocationList,
  TaskRequest,
  VerifiableCredential,
} from "./types";

export interface PolicyConfig {
  /** DIDs of principals this verifier accepts as roots of authority (e.g. the human/company an agent acts for). */
  trustedRootDids: string[];
  /**
   * Above this amount (in the task's currency), authorization alone is not
   * enough: the requester must also show reputation evidence (a vouch from a
   * trusted root, or a clean completed-task history). Keeps a single stolen
   * "authorization" credential from being sufficient for high-stakes asks.
   */
  reputationThreshold: number;
  /** Minimum completed, non-disputed receipts to satisfy the reputation gate when no direct vouch exists. */
  minCleanReceipts: number;
}

export interface EvaluateInput {
  requesterDid: string;
  credentials: VerifiableCredential[];
  revocationLists: RevocationList[];
  task: TaskRequest;
  config: PolicyConfig;
  now?: Date;
}

function findRevocationList(
  lists: RevocationList[],
  issuer: string,
  statusListId: string | undefined
): RevocationList | undefined {
  if (!statusListId) return undefined;
  return lists.find((l) => l.issuer === issuer && l.id === statusListId);
}

export function evaluate(input: EvaluateInput): PolicyResult {
  const now = input.now ?? new Date();
  const trace: PolicyStep[] = [];

  // --- 1. Identity -----------------------------------------------------
  const identityOk = isValidDidKey(input.requesterDid);
  trace.push({
    step: "Identity resolution",
    passed: identityOk,
    detail: identityOk
      ? `${input.requesterDid} is a self-certifying did:key — no registry lookup required.`
      : `${input.requesterDid} is not a recognizable identifier.`,
  });
  if (!identityOk) {
    return { decision: "REFUSE", trace };
  }

  // --- 2. Claims: verify every presented credential's signature + freshness, and revocation ---
  type Checked = {
    vc: VerifiableCredential;
    valid: boolean;
    reasons: string[];
  };
  const checked: Checked[] = input.credentials.map((vc) => {
    const sigCheck = verifyCredential(vc, now);
    const reasons = [...sigCheck.reasons];
    let valid = sigCheck.valid;

    if (valid && vc.credentialStatus) {
      const list = findRevocationList(input.revocationLists, vc.issuer, vc.credentialStatus.id);
      if (!list) {
        valid = false;
        reasons.push(`no revocation list available for issuer ${vc.issuer} (cannot confirm not-revoked)`);
      } else {
        const listCheck = verifyRevocationList(list);
        if (!listCheck.valid) {
          valid = false;
          reasons.push(`issuer's revocation list failed verification: ${listCheck.reasons.join(", ")}`);
        } else if (isRevoked(list, vc.id)) {
          valid = false;
          reasons.push(`credential ${vc.id} was revoked by its issuer on ${list.updated}`);
        }
      }
    }

    return { vc, valid, reasons };
  });

  const sigStepPassed = checked.every((c) => c.valid);
  trace.push({
    step: "Credential verification (signature, expiry, revocation)",
    passed: checked.length > 0 ? sigStepPassed : true,
    detail:
      checked.length === 0
        ? "No credentials were presented."
        : checked
            .map((c) => `${credentialLabel(c.vc)}: ${c.valid ? "valid" : `INVALID (${c.reasons.join("; ")})`}`)
            .join(" | "),
  });

  const validAuthorizations = checked.filter(
    (c) => c.valid && c.vc.type[1] === "AuthorizationCredential" && c.vc.credentialSubject.id === input.requesterDid
  ) as { vc: VerifiableCredential<AuthorizationSubject>; valid: true; reasons: string[] }[];

  // --- 3. Policy: authorization scope ------------------------------------------------
  const fromTrustedRoot = validAuthorizations.filter((c) => input.config.trustedRootDids.includes(c.vc.issuer));

  const scopeMatches = fromTrustedRoot.filter((c) => {
    const scope = c.vc.credentialSubject.scope;
    if (!scope.actions.includes(input.task.action)) return false;
    if (input.task.amount !== undefined) {
      if (scope.maxAmount === undefined) return false;
      if (scope.maxAmount < input.task.amount) return false;
      if (input.task.currency && scope.currency && scope.currency !== input.task.currency) return false;
    }
    if (input.task.resource && scope.resources && !scope.resources.includes(input.task.resource)) return false;
    return true;
  });

  let authPassed = scopeMatches.length > 0;
  let authDetail: string;
  if (authPassed) {
    const match = scopeMatches[0] as { vc: VerifiableCredential<AuthorizationSubject> };
    const amountClause =
      input.task.amount !== undefined
        ? `, up to ${match.vc.credentialSubject.scope.maxAmount} ${match.vc.credentialSubject.scope.currency ?? ""}`.trimEnd()
        : "";
    authDetail = `${match.vc.id} from trusted principal ${match.vc.issuer} covers action "${input.task.action}"${amountClause}.`;
  } else if (fromTrustedRoot.length > 0) {
    const attempted = fromTrustedRoot[0] as { vc: VerifiableCredential<AuthorizationSubject> };
    const scope = attempted.vc.credentialSubject.scope;
    authDetail = `${attempted.vc.id} is valid and from a trusted principal, but its scope (actions: [${scope.actions.join(
      ", "
    )}], maxAmount: ${scope.maxAmount ?? "n/a"} ${scope.currency ?? ""}) does not cover the request (action "${
      input.task.action
    }"${input.task.amount !== undefined ? `, amount ${input.task.amount} ${input.task.currency ?? ""}` : ""}). Scope exceeded.`;
  } else if (validAuthorizations.length > 0) {
    authDetail = `An authorization credential exists for ${input.requesterDid}, but its issuer is not on the trusted-principal list.`;
  } else {
    authDetail = `No valid AuthorizationCredential for ${input.requesterDid} covering "${input.task.action}" was presented.`;
  }
  trace.push({ step: "Authorization scope check", passed: authPassed, detail: authDetail });

  if (!authPassed) {
    return { decision: "REFUSE", trace };
  }

  // --- 4. Policy: reputation gate for high-stakes actions ------------------------
  const requiresReputationGate = (input.task.amount ?? 0) > input.config.reputationThreshold;
  if (requiresReputationGate) {
    const validVouches = checked.filter(
      (c) =>
        c.valid &&
        c.vc.type[1] === "AttestationCredential" &&
        c.vc.credentialSubject.id === input.requesterDid &&
        input.config.trustedRootDids.includes(c.vc.issuer) &&
        ((c.vc.credentialSubject as AttestationSubject).strength === "high" ||
          (c.vc.credentialSubject as AttestationSubject).strength === "medium")
    );

    const cleanReceipts = checked.filter(
      (c) =>
        c.valid &&
        c.vc.type[1] === "ActionReceiptCredential" &&
        c.vc.credentialSubject.id === input.requesterDid &&
        (c.vc.credentialSubject as ActionReceiptSubject).outcome === "completed"
    );
    const disputedReceipts = checked.filter(
      (c) =>
        c.valid &&
        c.vc.type[1] === "ActionReceiptCredential" &&
        c.vc.credentialSubject.id === input.requesterDid &&
        (c.vc.credentialSubject as ActionReceiptSubject).outcome === "disputed"
    );

    const reputationPassed =
      disputedReceipts.length === 0 &&
      (validVouches.length > 0 || cleanReceipts.length >= input.config.minCleanReceipts);

    trace.push({
      step: `Reputation check (required above ${input.config.reputationThreshold} ${input.task.currency ?? ""})`,
      passed: reputationPassed,
      detail: reputationPassed
        ? `${validVouches.length} trusted vouch(es) and ${cleanReceipts.length} completed receipt(s), ${disputedReceipts.length} disputed.`
        : disputedReceipts.length > 0
        ? `${disputedReceipts.length} disputed action receipt(s) on record — high-stakes request blocked pending resolution.`
        : `Requires either a trusted vouch or ${input.config.minCleanReceipts}+ completed receipts; found ${validVouches.length} vouch(es) and ${cleanReceipts.length} clean receipt(s).`,
    });

    if (!reputationPassed) {
      return { decision: "REFUSE", trace };
    }
  }

  const matched = scopeMatches[0] as { vc: VerifiableCredential<AuthorizationSubject> };
  return { decision: "ACCEPT", trace, matchedCredentialId: matched.vc.id };
}

function credentialLabel(vc: VerifiableCredential): string {
  return `${vc.type[1]}(${vc.id.slice(-8)})`;
}
