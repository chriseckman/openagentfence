import { describe, expect, it } from "vitest";
import {
  secureDefaultPolicyEngine,
  SECURE_DEFAULT_POLICY_HASH,
  emptyPolicyRuntimeState,
  secureDefaultEnvelope,
} from "../src/index.js";

describe("secure default policy engine", () => {
  it("blocks a cross-origin navigate with a stable reason", () => {
    const env = secureDefaultEnvelope("t");
    const decision = secureDefaultPolicyEngine.evaluate({
      action: {
        type: "NAVIGATE",
        destination: "https://evil.example",
        target: { origin: "https://shop.example" },
        instructionProvenance: { trust: "application" },
      },
      envelope: env,
      riskState: "NORMAL",
      runtimeState: emptyPolicyRuntimeState,
    });
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasons).toContain("destination_not_allowed");
    expect(decision.policyHash).toBe(SECURE_DEFAULT_POLICY_HASH);
  });

  it("allows a read", () => {
    const decision = secureDefaultPolicyEngine.evaluate({
      action: { type: "READ", instructionProvenance: { trust: "application" } },
      envelope: secureDefaultEnvelope("t"),
      riskState: "NORMAL",
      runtimeState: emptyPolicyRuntimeState,
    });
    expect(decision.verdict).toBe("ALLOW");
    expect(decision.reasons).toEqual([]);
  });

  it("is deterministic and replayable", () => {
    const input: import("../src/index.js").PolicyEvaluationInput = {
      action: { type: "READ", instructionProvenance: { trust: "application" } },
      envelope: secureDefaultEnvelope("t"),
      riskState: "NORMAL",
      runtimeState: emptyPolicyRuntimeState,
    };
    expect(secureDefaultPolicyEngine.evaluate(input)).toEqual(
      secureDefaultPolicyEngine.evaluate(input),
    );
  });
});
