# Notes

## AI tools used

This project was built with Claude Code (Anthropic). Claude wrote the trust
engine (`src/lib/trust`), the demo scenarios and Next.js app, the test suite,
and this documentation, in an interactive session with a human directing
scope, tech-stack choices, and reviewing output at each stage (tests run and
passing, `tsc --noEmit` clean, `next build` clean, and the live-server API
smoke-tested end to end before being called done). No other AI/codegen tools
were used.

## Key decisions

- **did:key over did:web/did:ion.** did:key needs no registry, DNS, or
  ledger — it resolves from the string alone. That fits a demo that has to
  work with zero external infrastructure, and it's a real, specified method
  (not an invented format), which satisfies "uses/extends an existing
  standard" without pulling in a full DID resolver stack.
- **A hand-rolled Verifiable-Credential-*shaped* format, not full JSON-LD.**
  Real VC tooling (`did-jwt-vc`, full JSON-LD `@context` processing) adds
  dependency weight and JSON-LD's dynamic remote-context-fetching semantics
  for very little demo value. The credential shape (issuer, credentialSubject,
  proof, credentialStatus) mirrors the W3C data model closely enough to port
  to a real VC library later without a redesign.
- **Categorical vouch strength (`low`/`medium`/`high`), not a numeric score.**
  This was a direct response to the brief's disqualifier ("a reputation
  score with no underlying mechanism"). Every "how much do we trust this"
  question in the system resolves to either a boolean policy check or a
  labeled category that's paired with the rule that produced it — never a
  bare number.
- **Revocation checked separately from signature validity.** Conflating them
  would make "why was this refused" ambiguous in exactly the cases (offboarding,
  incident response) where the distinction matters most operationally.
- **Stateless verification.** The demo API holds no session/database state;
  a scenario's full, pre-signed credential bundle is generated once per
  server instance and re-verified from scratch on every `/api/evaluate`
  call. This mirrors how a real verifier works (it doesn't need to have
  seen a credential before to check it) and means the "live demo" has zero
  infrastructure to keep running.
- **Six fixed scenarios rather than free-form credential editing in the UI.**
  Given the 90-second-explainability requirement, a curated set that always
  reproduces the same, correct trace was judged more valuable than an
  open-ended editor that could produce confusing or malformed states on
  stage. The underlying engine (`evaluate()`) is fully general — it takes
  arbitrary DIDs, credentials, and task requests — the demo layer is just a
  thin, fixed presentation of it.

## Out of scope

- **Delegation chains.** `AuthorizationScope.delegable` exists but
  multi-hop delegation (root → agent → sub-agent) is not verified by the
  policy engine yet; only direct issuance by a trusted root is checked.
- **Key rotation / recovery.** A lost private key currently means a lost
  DID; there's no rotation credential or recovery mechanism.
- **A persistent credential store or real network transport between agents.**
  Everything runs in one process; two agents "negotiating" is simulated by
  passing credential JSON directly, not over a wire protocol (DIDComm, A2A,
  etc.).
- **UI credential tampering sandbox.** The forged-credential attack is a
  fixed scenario built server-side, rather than letting a user edit a
  credential's JSON live in the browser and watch it fail (a nice future
  addition, not required for the failure-test deliverable).
