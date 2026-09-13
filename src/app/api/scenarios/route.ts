import { NextResponse } from "next/server";
import { getScenarios, getWorldSummary } from "@/lib/demo/scenarios";

export const runtime = "nodejs";

export async function GET() {
  const scenarios = getScenarios().map((s) => ({
    id: s.id,
    title: s.title,
    narrative: s.narrative,
    requesterLabel: s.requesterLabel,
    verifierLabel: s.verifierLabel,
    task: s.task,
    expected: s.expected,
    attack: s.attack,
    attackDescription: s.attackDescription,
    credentials: s.credentials,
  }));

  return NextResponse.json({ world: getWorldSummary(), scenarios });
}
