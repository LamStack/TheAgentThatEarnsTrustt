# Failure test: attacking the trust layer

A trust system that has never been attacked is untested. This project ships
three concrete attack scenarios, each implemented as both an automated test
(`test/policy.test.ts`, describe block "attack scenarios") and a selectable
scenario in the live demo (`/demo`). All three are caught.

## Attack 1 — Forged authorization (signature attack)

**Setup.** Atlas holds a real, validly-issued `AuthorizationCredential` from
Aurora Logistics capping his spend at $800. An attacker ("Mallory") copies the
credential's JSON and edits `credentialSubject.scope.maxAmount` from `800` to
`50000`, then presents it to book a $42,000 flight.

**Why it should fail.** Mallory does not have Aurora's private key. She can
edit the JSON, but she cannot produce a signature over the edited bytes that
verifies against Aurora's public key.

**What catches it.** `verifyCredential()` recomputes the canonical bytes of
the (edited) credential and checks the *existing* signature against them.
Canonicalization means every field — including deeply nested ones — is part
of what's signed, so the mismatch is detected immediately:

```
✗ Credential verification (signature, expiry, revocation)
  AuthorizationCredential(...): INVALID (signature invalid: credential
  content does not match issuer's signature)
✗ Authorization scope check
  No valid AuthorizationCredential ... was presented.
```

Decision: **REFUSE.** Test: `"catches a forged credential: subject silently
raised their own spending cap"` in `test/policy.test.ts`.

## Attack 2 — Replayed revoked credential

**Setup.** Aurora issued Atlas an earlier authorization, then revoked it
during a security review (published in its signed status list). Atlas — or
someone who obtained the old credential — presents it again.

**Why it should fail.** The credential's signature is still perfectly valid;
Aurora really did sign it once. Revocation is a separate, later fact that the
signature alone cannot encode.

**What catches it.** The policy engine fetches Aurora's *current* status
list, verifies the list's own signature (so an attacker can't just publish a
falsified "not revoked" list), and checks whether this credential's id is on
it:

```
✗ Credential verification (signature, expiry, revocation)
  AuthorizationCredential(...): INVALID (credential ... was revoked by its
  issuer on 2026-09-05T00:00:00.000Z)
```

Decision: **REFUSE.** Tests: `"catches a revoked credential presented after
the fact"` and `"catches a credential replayed against a spoofed revocation
list from an impostor issuer"` (this second variant checks that a forged
"clean" status list, not signed by the real issuer, is itself rejected — the
system fails closed rather than trusting an unverifiable list).

## Attack 3 — Scope exceeded (a policy failure, not a crypto failure)

**Setup.** Atlas presents his real, current, unrevoked, correctly-signed
credential — capped at $800 for domestic travel — and asks to book a $4,800
flight.

**Why it should fail.** Nothing here is forged. This is the case that a
naive "is the signature valid?" check would wrongly accept. Authenticity and
authority are different questions.

**What catches it.** The authorization-scope step checks the requested
action, amount, and currency against the credential's granted scope
independently of signature validity:

```
✓ Credential verification (signature, expiry, revocation)
✗ Authorization scope check
  ... its scope (actions: [book_travel], maxAmount: 800 USD) does not cover
  the request (action "book_travel", amount 4800 USD). Scope exceeded.
```

Decision: **REFUSE.** Test: `"catches a scope-exceeded request from an
otherwise legitimate, unrevoked credential"`.

## Bonus case — self-issued authority

A fourth test (`"catches self-issued authority"`) confirms that an agent
cannot grant itself permission: an `AuthorizationCredential` where the issuer
equals the subject is only ever accepted if that issuer also happens to be on
the verifier's trusted-root list — which, for an ordinary agent, it never is.

## Running the failure tests yourself

```bash
npm test -- policy.test.ts
```

All scenarios are also reachable interactively at `/demo` — each shows the
same step-by-step trace, so the "why" is visible in the UI, not just in test
output.
