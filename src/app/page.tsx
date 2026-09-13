const STAGES = [
  {
    name: "Identity",
    detail:
      "Every agent generates its own Ed25519 keypair and derives a did:key identifier from the public key. No registry or ledger required — the DID is self-certifying.",
  },
  {
    name: "Claims",
    detail:
      "Principals (humans, companies, or other agents) issue signed Verifiable Credentials: authorization grants (scoped permissions), attestations (vouches), and action receipts (task history).",
  },
  {
    name: "Verification",
    detail:
      "A verifier checks each credential's signature against the issuer's did:key, its expiry, and its status against the issuer's independently-signed revocation list.",
  },
  {
    name: "Policy",
    detail:
      "A rule-based engine decides accept/refuse: does a valid, unrevoked authorization from a trusted principal cover this exact action, amount, and resource? For high-stakes actions, is there also reputation evidence?",
  },
];

export default function Home() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-14 sm:px-6">
      <p className="text-sm font-medium uppercase tracking-wide text-neutral-500">Trust layer for AI agents</p>
      <h1 className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">The Agent That Earns Trust</h1>
      <p className="mt-4 text-lg text-neutral-600">
        Agents negotiate, transact, and act on behalf of people and companies. This is a working identity,
        credential, and policy layer that lets one agent decide — verifiably, not by vibes — whether to accept a
        task from another.
      </p>

      <div className="mt-6 flex gap-3">
        <a href="/demo" className="rounded-lg bg-ink px-4 py-2 text-sm font-medium text-white hover:opacity-90">
          Open the live demo
        </a>
        <a
          href="https://github.com/LamStack/TheAgentThatEarnsTrustt"
          className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium hover:border-neutral-500"
        >
          View source
        </a>
      </div>

      <h2 className="mt-12 text-sm font-medium uppercase tracking-wide text-neutral-500">
        Architecture: identity → claims → verification → policy
      </h2>
      <ol className="mt-4 space-y-4">
        {STAGES.map((s, i) => (
          <li key={s.name} className="rounded-xl border border-neutral-200 bg-white p-4">
            <div className="flex items-baseline gap-3">
              <span className="text-xs font-mono text-neutral-400">0{i + 1}</span>
              <span className="font-medium">{s.name}</span>
            </div>
            <p className="mt-1 text-sm text-neutral-600">{s.detail}</p>
          </li>
        ))}
      </ol>

      <h2 className="mt-12 text-sm font-medium uppercase tracking-wide text-neutral-500">What's real here</h2>
      <ul className="mt-4 list-disc space-y-2 pl-5 text-neutral-700">
        <li>Real Ed25519 signing and verification (@noble/curves) — every credential in the demo is actually signed.</li>
        <li>did:key identities, W3C Verifiable-Credential-shaped claims, and a signed status list for revocation.</li>
        <li>A policy engine that produces an explainable trace, not a single opaque trust score.</li>
        <li>An attack suite: forged credentials, revoked credentials, and scope-exceeded requests are all caught.</li>
      </ul>

      <p className="mt-12 text-sm text-neutral-400">
        See <code>docs/ARCHITECTURE.md</code> for the full design, <code>docs/FAILURE_TEST.md</code> for the attack
        scenarios, and <code>docs/THESIS.md</code> for where this goes over the next two years.
      </p>
    </main>
  );
}
