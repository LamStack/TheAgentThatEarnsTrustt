# Two-year thesis: agent identity and reputation at scale

Within two years, every agent that transacts on someone's behalf will need a
portable identity that outlives any single platform. Today an agent's
"identity" is an API key scoped to one vendor's database; that breaks the
moment agents start negotiating directly with *other people's* agents,
because no counterparty can verify a claim rooted in infrastructure they
don't trust and can't see. `did:key`-style self-certifying identifiers (or
their successors) win not out of ideology, but because they're the only
shape that lets a stranger's agent verify a claim without calling home to
your database.

Reputation will not converge on a single portable score, and shouldn't. A
score compresses away what a counterparty needs for a context-specific call:
what this agent was authorized to do, by whom, and what happened last time. The winning pattern looks like credit reporting,
not a credit score alone — structured, disputable, per-domain claims
(vouches, receipts, scoped grants) that a *verifier's own policy* weighs,
rather than a black-box number the issuer hands you. Expect a small number
of attestation formats to standardize (a Verifiable-Credentials descendant
is the leading candidate) while the policy layer on top stays plural and
proprietary — that's where the competitive advantage actually lives.

The unresolved problem is revocation latency and delegation depth. A
compromised agent needs to be un-trusted in seconds, not on the next
status-list publish cycle, and multi-hop delegation (a company authorizes an
agent, which sub-authorizes a tool, which sub-authorizes a plugin) needs
chain-of-authority verification that stays cheap at depth. Whoever solves
revocation latency and bounded delegation — not whoever picks the prettiest
identity standard — defines the layer everyone else builds on. Insurance and
staking (authority backed by bonded capital, forfeit on a disputed receipt)
is the mechanism I'd bet on to make high-stakes delegation viable before
regulation catches up.
