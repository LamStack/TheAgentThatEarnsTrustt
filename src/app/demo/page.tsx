"use client";

import { useEffect, useState } from "react";

interface Task {
  action: string;
  amount?: number;
  currency?: string;
  resource?: string;
}

interface Scenario {
  id: string;
  title: string;
  narrative: string;
  requesterLabel: string;
  verifierLabel: string;
  task: Task;
  expected: "ACCEPT" | "REFUSE";
  attack: boolean;
  attackDescription?: string;
  credentials: any[];
}

interface WorldSummary {
  principals: { did: string; label: string }[];
  agents: { did: string; label: string }[];
  config: { trustedRootDids: string[]; reputationThreshold: number; minCleanReceipts: number };
}

interface PolicyStep {
  step: string;
  passed: boolean;
  detail: string;
}

interface PolicyResult {
  decision: "ACCEPT" | "REFUSE";
  trace: PolicyStep[];
  matchedCredentialId?: string;
}

function shortDid(did: string): string {
  return `${did.slice(0, 14)}…${did.slice(-6)}`;
}

function taskLabel(task: Task): string {
  const amount = task.amount !== undefined ? `${task.currency ?? ""} ${task.amount.toLocaleString()}`.trim() : null;
  const parts = [task.action.replace(/_/g, " ")];
  if (amount) parts.push(`(${amount})`);
  if (task.resource) parts.push(`· ${task.resource}`);
  return parts.join(" ");
}

export default function DemoPage() {
  const [world, setWorld] = useState<WorldSummary | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [visibleSteps, setVisibleSteps] = useState(0);
  const [result, setResult] = useState<PolicyResult | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    fetch("/api/scenarios")
      .then((r) => r.json())
      .then((data) => {
        setWorld(data.world);
        setScenarios(data.scenarios);
        setSelectedId(data.scenarios[0]?.id ?? null);
      });
  }, []);

  const selected = scenarios.find((s) => s.id === selectedId) ?? null;

  async function runVerification() {
    if (!selected) return;
    setRunning(true);
    setResult(null);
    setVisibleSteps(0);

    const res = await fetch("/api/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: selected.id }),
    });
    const data = await res.json();
    const policyResult: PolicyResult = data.result;
    setResult(policyResult);

    for (let i = 1; i <= policyResult.trace.length; i++) {
      await new Promise((r) => setTimeout(r, 420));
      setVisibleSteps(i);
    }
    setRunning(false);
  }

  function selectScenario(id: string) {
    setSelectedId(id);
    setResult(null);
    setVisibleSteps(0);
    setShowRaw(false);
  }

  return (
    <main className="mx-auto max-w-5xl px-4 py-10 sm:px-6">
      <header className="mb-8">
        <a href="/" className="text-sm text-neutral-500 hover:underline">
          &larr; The Agent That Earns Trust
        </a>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl">Trust-gated task demo</h1>
        <p className="mt-2 max-w-2xl text-neutral-600">
          Pick a scenario below. Each one presents a real, cryptographically signed credential bundle to a verifier
          agent, which runs the same four-stage check every time:{" "}
          <span className="font-medium text-neutral-900">identity → claims → verification → policy</span>.
        </p>
      </header>

      <section className="grid gap-3 sm:grid-cols-2">
        {scenarios.map((s) => (
          <button
            key={s.id}
            onClick={() => selectScenario(s.id)}
            className={`rounded-xl border p-4 text-left transition ${
              selectedId === s.id
                ? "border-ink bg-white shadow-sm"
                : "border-neutral-200 bg-white/60 hover:border-neutral-400"
            }`}
          >
            <div className="mb-1 flex items-center gap-2">
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                  s.attack
                    ? "bg-red-100 text-red-700"
                    : s.expected === "REFUSE"
                    ? "bg-amber-100 text-amber-800"
                    : "bg-emerald-100 text-emerald-700"
                }`}
              >
                {s.attack ? "Attack" : s.expected === "REFUSE" ? "Policy refusal" : "Legitimate"}
              </span>
              <span className="text-xs text-neutral-400">{s.expected}</span>
            </div>
            <div className="font-medium">{s.title}</div>
          </button>
        ))}
      </section>

      {selected && (
        <section className="mt-8 rounded-2xl border border-neutral-200 bg-white p-5 sm:p-7">
          <p className="text-neutral-700">{selected.narrative}</p>

          <div className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
            <div className="rounded-lg bg-neutral-50 p-3">
              <div className="text-neutral-400">Requester</div>
              <div className="font-medium">{selected.requesterLabel}</div>
            </div>
            <div className="rounded-lg bg-neutral-50 p-3">
              <div className="text-neutral-400">Verifier</div>
              <div className="font-medium">{selected.verifierLabel}</div>
            </div>
            <div className="rounded-lg bg-neutral-50 p-3">
              <div className="text-neutral-400">Requested task</div>
              <div className="font-medium">{taskLabel(selected.task)}</div>
            </div>
          </div>

          {selected.attackDescription && (
            <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
              <span className="font-medium">Why this matters:</span> {selected.attackDescription}
            </div>
          )}

          <div className="mt-5 flex items-center gap-3">
            <button
              onClick={runVerification}
              disabled={running}
              className="rounded-lg bg-ink px-4 py-2 text-sm font-medium text-white transition hover:opacity-90 disabled:opacity-50"
            >
              {running ? "Verifying…" : "Run verification"}
            </button>
            <button
              onClick={() => setShowRaw((v) => !v)}
              className="text-sm text-neutral-500 underline underline-offset-2 hover:text-neutral-800"
            >
              {showRaw ? "Hide" : "Show"} presented credentials (JSON)
            </button>
          </div>

          {showRaw && (
            <pre className="mt-4 max-h-72 overflow-auto rounded-lg bg-neutral-900 p-4 text-xs text-neutral-100">
              {JSON.stringify(selected.credentials, null, 2)}
            </pre>
          )}

          {result && (
            <div className="mt-6">
              <ol className="space-y-2">
                {result.trace.slice(0, visibleSteps).map((step, i) => (
                  <li
                    key={i}
                    className={`flex gap-3 rounded-lg border p-3 text-sm ${
                      step.passed ? "border-emerald-200 bg-emerald-50" : "border-red-200 bg-red-50"
                    }`}
                  >
                    <span className={step.passed ? "text-emerald-600" : "text-red-600"}>
                      {step.passed ? "✓" : "✗"}
                    </span>
                    <div>
                      <div className="font-medium">{step.step}</div>
                      <div className="mt-0.5 text-neutral-600">{step.detail}</div>
                    </div>
                  </li>
                ))}
              </ol>

              {visibleSteps >= result.trace.length && (
                <div
                  className={`mt-5 rounded-xl p-5 text-center text-lg font-semibold ${
                    result.decision === "ACCEPT" ? "bg-emerald-600 text-white" : "bg-red-600 text-white"
                  }`}
                >
                  {result.decision === "ACCEPT" ? "Task accepted" : "Task refused"}
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {world && (
        <section className="mt-8 text-xs text-neutral-400">
          Trusted root: {world.principals[0]?.label} ({shortDid(world.principals[0]?.did ?? "")}) · Reputation
          threshold: {world.config.reputationThreshold} · Min clean receipts: {world.config.minCleanReceipts}
        </section>
      )}
    </main>
  );
}
