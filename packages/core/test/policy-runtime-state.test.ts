import { describe, expect, it } from "vitest";
import {
  createPolicyRuntimeState,
  emptyPolicyRuntimeState,
  isValidatedPolicyRuntimeState,
} from "../src/index.js";

describe("policy runtime state", () => {
  it("brands and freezes only bounded deterministic summaries", () => {
    const state = createPolicyRuntimeState({
      budget: { actionsUsed: 1, navigationsUsed: 2, elapsedMs: 3 },
      scannerEvidence: [
        {
          scannerId: "scanner",
          ruleId: "rule",
          origin: "https://example.test",
          kind: "deterministic",
          outcome: "finding",
          severity: "high",
        },
      ],
    });
    expect(isValidatedPolicyRuntimeState(state)).toBe(true);
    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.scannerEvidence[0])).toBe(true);
  });

  it("rejects semantic/arbitrary evidence and invalid counters", () => {
    expect(() =>
      createPolicyRuntimeState({
        budget: { actionsUsed: -1, navigationsUsed: 0, elapsedMs: 0 },
        scannerEvidence: [],
      }),
    ).toThrow();
    expect(() =>
      createPolicyRuntimeState({
        budget: { actionsUsed: 0, navigationsUsed: 0, elapsedMs: 0 },
        scannerEvidence: [
          { scannerId: "s", ruleId: "r", kind: "semantic", outcome: "finding", severity: "high" },
        ],
      }),
    ).toThrow();
    const inherited = Object.create({ budget: {}, scannerEvidence: [] }) as object;
    expect(() => createPolicyRuntimeState(inherited)).toThrow();
    expect(emptyPolicyRuntimeState.budget.actionsUsed).toBe(0);
  });
});
