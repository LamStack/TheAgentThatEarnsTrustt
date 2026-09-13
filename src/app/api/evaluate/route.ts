import { NextResponse } from "next/server";
import { getScenarios, config } from "@/lib/demo/scenarios";
import { evaluate } from "@/lib/trust";

export const runtime = "nodejs";

/**
 * Runs the real policy engine (signature verification, revocation checks,
 * scope checks, reputation gate) server-side for the requested scenario.
 * This is not a canned response: every call re-verifies every credential's
 * Ed25519 signature and re-checks the revocation list from scratch.
 */
export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  const scenarioId = body?.scenarioId;
  if (typeof scenarioId !== "string") {
    return NextResponse.json({ error: "scenarioId is required" }, { status: 400 });
  }

  const scenario = getScenarios().find((s) => s.id === scenarioId);
  if (!scenario) {
    return NextResponse.json({ error: `unknown scenario: ${scenarioId}` }, { status: 404 });
  }

  const result = evaluate({
    requesterDid: scenario.requesterDid,
    credentials: scenario.credentials,
    revocationLists: scenario.revocationLists,
    task: scenario.task,
    config,
    now: new Date(),
  });

  return NextResponse.json({ scenarioId, result });
}
