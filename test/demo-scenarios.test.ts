import { describe, expect, it } from "vitest";
import { getScenarios, config } from "@/lib/demo/scenarios";
import { evaluate } from "@/lib/trust";

describe("demo scenarios match their advertised outcome", () => {
  const scenarios = getScenarios();

  it("has at least one accept, one attack, and one pure-policy refusal", () => {
    expect(scenarios.some((s) => s.expected === "ACCEPT")).toBe(true);
    expect(scenarios.some((s) => s.attack)).toBe(true);
    expect(scenarios.some((s) => !s.attack && s.expected === "REFUSE")).toBe(true);
  });

  for (const scenario of getScenarios()) {
    it(`"${scenario.title}" resolves to ${scenario.expected}`, () => {
      const result = evaluate({
        requesterDid: scenario.requesterDid,
        credentials: scenario.credentials,
        revocationLists: scenario.revocationLists,
        task: scenario.task,
        config,
        now: new Date("2026-09-13"),
      });
      expect(result.decision).toBe(scenario.expected);
    });
  }
});
