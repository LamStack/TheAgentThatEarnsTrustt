# Architecture: identity → claims → verification → policy

This system has four layers. Each is independent and individually testable; a
decision at the top (policy) is only ever as strong as the layers under it.

```
 ┌────────────┐      ┌────────────────┐      ┌───────────────────┐      ┌────────────────┐
 │  IDENTITY  │ ───▶ │     CLAIMS      │ ───▶ │   VERIFICATION     │ ───▶ │     POLICY      │
 │  did:key   │      │ Verifiable      │      │ signature + expiry │      │ scope + trust   │
 │  (Ed25519) │      │ Credentials     │      │ + revocation       │      │ threshold check │
 └────────────┘      └────────────────┘      └───────────────────┘      └────────────────┘
```

## 1. Identity — `src/lib/trust/did.ts`, `crypto.ts`

Every agent (and every human/company principal) generates its own Ed25519
keypair and derives a `did:key` identifier directly from the public key:

```
did:key:z6Mk...   =   "did:key:z" + base58btc( [0xed, 0x01] ++ publicKeyBytes )
```

This is the [`did:key` method](https://w3c-ccg.github.io/did-method-key/): the
identifier is **self-certifying**. Anyone can recover the public key from the
DID string alone — no blockchain, no DNS, no central registry, no network
call. `didToPublicKey()` is a pure function. This is what makes the rest of
the system work offline and without a trusted intermediary.

## 2. Claims — `src/lib/trust/credentials.ts`, `types.ts`

Claims are signed JSON documents shaped like the
[W3C Verifiable Credentials data model](https://www.w3.org/TR/vc-data-model-2.0/):
`issuer`, `credentialSubject`, `issuanceDate`/`expirationDate`, an optional
`credentialStatus` pointer, and a `proof` (an Ed25519 signature over the
canonicalized document). Three credential types cover the brief's three asks:

| Type | Answers | Issued by |
|---|---|---|
| `AuthorizationCredential` | "What is this agent scoped to do?" (actions, max amount, currency, resources, delegability) | A principal (human/company) or another authority |
| `AttestationCredential` | "Who vouches for this agent, and how strongly?" (categorical `low`/`medium`/`high`, plus a domain and a human-readable statement — never a bare number) | Any agent or principal willing to stake its own reputation on the claim |
| `ActionReceiptCredential` | "What has this agent actually done?" (`completed`/`failed`/`disputed`, tied to a specific counterparty and task) | The counterparty of a completed interaction |

Signing uses a minimal JSON Canonicalization Scheme (`canonical.ts`, a subset
of RFC 8785): object keys are sorted recursively before serialization, so the
same logical document always signs to the same bytes and any edit — even to a
single nested field — changes the signed bytes and invalidates the signature.

## 3. Verification — `credentials.ts`, `revocation.ts`

Verifying a presented credential is three independent checks, deliberately
kept separate so failures stay explainable instead of collapsing into one
opaque "invalid":

1. **Signature.** Recompute the canonical bytes of the credential (minus its
   `proof`), resolve the issuer's public key from their `did:key`, and verify
   the Ed25519 signature. A single tampered field fails this.
2. **Temporal validity.** `issuanceDate` not in the future; `expirationDate`
   (if present) not passed.
3. **Revocation.** If the credential carries a `credentialStatus`, fetch the
   issuer's current status list (a signed `RevocationList` — the same role as
   [`StatusList2021`](https://w3c.github.io/vc-bitstring-status-list/)) and
   check membership. The list is itself an Ed25519-signed document, verified
   the same way a credential is — a verifier never has to trust whoever is
   hosting or relaying the list, only the issuer's key. **A credential whose
   status cannot be confirmed is treated as not-yet-trusted, not innocent —
   the system fails closed.**

## 4. Policy — `src/lib/trust/policy.ts`

`evaluate()` takes a requester DID, a bundle of presented credentials, the
relevant revocation lists, and a `TaskRequest` (action, amount, currency,
resource), and produces a `PolicyResult`: an `ACCEPT`/`REFUSE` decision plus
an ordered `trace` of named steps, each with a pass/fail and a human-readable
reason. Nothing is compressed into a single score. The steps are:

1. **Identity resolution** — is the requester DID well-formed?
2. **Credential verification** — per the layer above, for every presented credential.
3. **Authorization scope check** — is there a valid, unrevoked `AuthorizationCredential`,
   issued by a principal this verifier recognizes as trusted, whose scope
   (`actions`, `maxAmount`+`currency`, `resources`) actually covers this exact
   request? An authorization from an untrusted issuer, or one that covers a
   different action or a smaller amount, fails here — distinctly from a
   cryptographic failure.
4. **Reputation gate** (only above a configured `reputationThreshold`) — for
   high-stakes actions, a valid authorization is necessary but not
   sufficient. The requester must also show either a trusted vouch
   (`AttestationCredential` of `medium`/`high` strength from a trusted
   principal) or a minimum number of clean completed `ActionReceiptCredential`s
   — and a single unresolved `disputed` receipt vetoes acceptance outright,
   regardless of anything else presented.

See [`src/lib/demo/scenarios.ts`](../src/lib/demo/scenarios.ts) for six
worked scenarios and [`FAILURE_TEST.md`](./FAILURE_TEST.md) for the three
attacks this pipeline is specifically built to catch.

## Trust profile — a structured summary, not a score

`buildTrustProfile()` (`trustProfile.ts`) aggregates an agent's held
credentials into a `TrustProfile`: its authorizations (with issuer trust and
scope), its vouches (with strength), its action history
(completed/failed/disputed counts), and a `standing` label
(`Unestablished`/`Provisional`/`Established`) that is **always returned
together with the rule that produced it** (e.g. "Has a valid authorization
from a trusted principal, and either 2+ completed receipts or a
medium/high-strength vouch"). The label is a rendering convenience for a UI;
the rule is the actual fact, and it's always inspectable.

## What's out of scope (see NOTES.md)

- Delegation chains (an authority re-delegating a narrower scope to a
  sub-agent) — the `delegable` flag exists on `AuthorizationScope` but the
  policy engine only checks direct issuance by a trusted root today.
- A real did:web / did:ion resolver, or interop with other did:key
  implementations' test vectors.
- Persistent storage — the demo is intentionally stateless (see NOTES.md).
