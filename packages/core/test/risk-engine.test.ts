import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { applyRiskSignal, DEFAULT_RISK_POLICY, stateForScore } from "../src/index.js";
import type { SessionRisk } from "../src/index.js";

describe("risk engine", () => {
  it("uses the exact v0.1 score boundaries", () => {
    expect(stateForScore(39)).toBe("NORMAL");
    expect(stateForScore(40)).toBe("RESTRICTED");
    expect(stateForScore(79)).toBe("RESTRICTED");
    expect(stateForScore(80)).toBe("READ_ONLY");
    expect(stateForScore(119)).toBe("READ_ONLY");
    expect(stateForScore(120)).toBe("QUARANTINED");
  });

  it("uses the decided default weights and never decreases authority", () => {
    let risk: SessionRisk = { state: "NORMAL", score: 0 };
    risk = applyRiskSignal(risk, "hidden_injection").current;
    expect(risk).toEqual({ state: "RESTRICTED", score: 40 });
    risk = applyRiskSignal(risk, "cross_origin_redirect").current;
    expect(risk).toEqual({ state: "RESTRICTED", score: 60 });
    risk = applyRiskSignal(risk, "secret_requested").current;
    expect(risk).toEqual({ state: "READ_ONLY", score: 110 });
    risk = applyRiskSignal(risk, "unrelated_tab").current;
    expect(risk).toEqual({ state: "QUARANTINED", score: 140 });
  });

  it("forces injection and critical transitions regardless of score", () => {
    expect(
      applyRiskSignal({ state: "NORMAL", score: 0 }, "high_confidence_injection").current,
    ).toEqual({
      state: "RESTRICTED",
      score: DEFAULT_RISK_POLICY.hiddenInjectionWeight,
    });
    expect(applyRiskSignal({ state: "NORMAL", score: 0 }, "critical_finding").current).toEqual({
      state: "QUARANTINED",
      score: 0,
    });
  });

  it("is monotonic under arbitrary signal sequences", () => {
    const signals = [
      "hidden_injection",
      "cross_origin_redirect",
      "secret_requested",
      "unrelated_tab",
      "high_confidence_injection",
      "critical_finding",
    ] as const;
    const rank: Record<SessionRisk["state"], number> = {
      NORMAL: 0,
      RESTRICTED: 1,
      READ_ONLY: 2,
      QUARANTINED: 3,
    };
    fc.assert(
      fc.property(fc.array(fc.constantFrom(...signals), { maxLength: 100 }), (sequence) => {
        let risk: SessionRisk = { state: "NORMAL", score: 0 };
        for (const signal of sequence) {
          const next = applyRiskSignal(risk, signal).current;
          expect(rank[next.state]).toBeGreaterThanOrEqual(rank[risk.state]);
          expect(next.score).toBeGreaterThanOrEqual(risk.score);
          risk = next;
        }
      }),
      { numRuns: 200, seed: 20260818 },
    );
  });
});
