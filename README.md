# The Agent That Earns Trust

A working trust layer for AI agents: real Ed25519-signed identities and
credentials, a signed revocation registry, and a policy engine that decides —
with a fully explainable trace, not a score — whether one agent should accept
a task from another.

**Live demo:** deploy in ~1 minute with Vercel (see below) — no accounts, no
database, no env vars.
**Docs:** [Architecture](docs/ARCHITECTURE.md) · [Failure test](docs/FAILURE_TEST.md) · [Thesis](docs/THESIS.md) · [Notes](docs/NOTES.md)

## What this is

Two pages:

- **`/`** — the pitch and the architecture snapshot.
- **`/demo`** — six interactive scenarios. Each presents a real, signed
  credential bundle to a verifier agent and runs it through the same
  four-stage pipeline every time: **identity → claims → verification →
  policy**. Three are legitimate, three are attacks or policy refusals — see
  [`docs/FAILURE_TEST.md`](docs/FAILURE_TEST.md).

Everything shown is computed live, server-side, on every request — nothing
is precomputed or faked. `src/lib/trust` is a standalone, dependency-light
library (no framework coupling) that could be lifted into any other Node or
browser project.

## Quickstart

```bash
npm install
npm test          # 36 tests: crypto, DIDs, credentials, revocation, policy, attack scenarios
npm run typecheck
npm run dev        # http://localhost:3000
```

## Deploying the live demo

This is a zero-config Next.js app — no database, no environment variables,
no external services.

1. Push this repo to GitHub (already done if you're reading this there).
2. Go to [vercel.com/new](https://vercel.com/new), import the repo, and
   click **Deploy**. Vercel auto-detects Next.js; no configuration needed.
3. Your live URL is ready in under a minute.

(Netlify works the same way via `netlify.com/start` with the Next.js
runtime plugin, which Netlify enables automatically for a detected Next.js
project.)

## Project layout

```
src/lib/trust/        the trust engine — identity, claims, verification, policy (framework-agnostic)
  crypto.ts              Ed25519 keypairs, sign, verify
  did.ts                 did:key encode/decode
  canonical.ts            deterministic JSON canonicalization for signing
  credentials.ts          issue/verify Verifiable Credentials
  revocation.ts           signed status lists
  policy.ts               evaluate(): the accept/refuse decision engine
  trustProfile.ts         explainable trust-profile aggregation
src/lib/demo/scenarios.ts  the six demo scenarios (all credentials really signed at server start)
src/app/                  Next.js pages + API routes (/api/scenarios, /api/evaluate)
test/                     vitest suite, including the attack-scenario tests
docs/                     architecture, failure test, thesis, notes
```

## Submission checklist

- [x] Public repo URL (this repo — clean clone + `npm install && npm test` runs green)
- [x] Live demo URL — deploy via the one-click steps above
- [ ] 90-second Loom walkthrough (record separately; suggested script: open
      `/demo`, run the legitimate scenario, then the forged-credential and
      revoked-credential attacks, narrating the trace as it appears)
- [x] Architecture snapshot — [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [x] Failure test — [`docs/FAILURE_TEST.md`](docs/FAILURE_TEST.md)
- [x] Two-year thesis (299 words) — [`docs/THESIS.md`](docs/THESIS.md)
- [x] Notes: AI tools used, key decisions, out of scope — [`docs/NOTES.md`](docs/NOTES.md)

## License

MIT
