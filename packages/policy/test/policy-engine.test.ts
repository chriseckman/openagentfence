import {
  createPolicyRuntimeState,
  compileTaskContract,
  validateTaskContract,
  type RiskState,
} from "@openagentfence/core";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  createPolicyEngine,
  hashPolicyDocument,
  loadPolicy,
  loadPolicyDocument,
  resolveScannerSuppression,
  resolveScannerThreshold,
  validatePolicy,
} from "../src/index.js";

function envelope() {
  const contract = validateTaskContract({
    task: "policy test",
    capabilities: { purchases: true, uploads: true, executeScript: true, navigation: "allowlist" },
    origins: { allow: ["https://shop.example"] },
  });
  if (!contract.ok) throw new Error("fixture contract invalid");
  return compileTaskContract(contract.value);
}

function runtime(overrides: Record<string, unknown> = {}) {
  return createPolicyRuntimeState({
    budget: { actionsUsed: 0, navigationsUsed: 0, elapsedMs: 0 },
    scannerEvidence: [],
    ...overrides,
  });
}

function action(type: "READ" | "PURCHASE" | "NAVIGATE" | "UNKNOWN" = "READ") {
  return {
    type,
    instructionProvenance: { trust: "application" as const },
    ...(type === "NAVIGATE"
      ? { destination: "https://shop.example/next", target: { origin: "https://shop.example" } }
      : {}),
  };
}

describe("document policy engine", () => {
  it("creates deterministic hashes regardless of object key order", async () => {
    const first = await loadPolicyDocument({
      version: 1,
      actions: { purchase: "approval" },
      budgets: { max_actions: 3 },
    });
    const second = await loadPolicyDocument({
      version: 1,
      budgets: { max_actions: 3 },
      actions: { purchase: "approval" },
    });
    expect(hashPolicyDocument(first)).toBe(hashPolicyDocument(second));
    expect(
      createPolicyEngine(first).evaluate({
        action: action("PURCHASE"),
        envelope: envelope(),
        riskState: "NORMAL",
        runtimeState: runtime(),
      }),
    ).toMatchObject({
      verdict: "REQUIRE_APPROVAL",
      reasons: ["approval_required"],
      matchedRules: ["actions.purchase"],
    });
  });

  it("honors budgets, scanner failures, injection, navigation, and unknown actions", async () => {
    const document = await loadPolicyDocument({
      version: 1,
      defaults: {
        unknown_action: "block",
        scanner_failure: { low_risk: "warn", high_risk: "block" },
      },
      navigation: { mode: "same-origin" },
      injection: { high_confidence: "restricted_mode", critical: "quarantine" },
      budgets: { max_actions: 1, on_exceeded: "block" },
    });
    const engine = createPolicyEngine(document);
    const input = { envelope: envelope(), riskState: "NORMAL" as const };
    expect(
      engine.evaluate({
        ...input,
        action: action(),
        runtimeState: runtime({ budget: { actionsUsed: 1, navigationsUsed: 0, elapsedMs: 0 } }),
      }).reasons,
    ).toContain("budget_exceeded");
    expect(
      engine.evaluate({
        ...input,
        action: action(),
        runtimeState: runtime({
          scannerEvidence: [
            {
              scannerId: "s",
              ruleId: "r",
              kind: "deterministic",
              outcome: "failure",
              severity: "low",
            },
          ],
        }),
      }).verdict,
    ).toBe("WARN");
    expect(
      engine.evaluate({
        ...input,
        action: action(),
        runtimeState: runtime({
          scannerEvidence: [
            {
              scannerId: "injection",
              ruleId: "r",
              kind: "deterministic",
              outcome: "finding",
              severity: "high",
            },
          ],
        }),
      }).verdict,
    ).toBe("RESTRICT");
    expect(
      engine.evaluate({
        ...input,
        action: { ...action("NAVIGATE"), destination: "https://other.example/" },
        runtimeState: runtime(),
      }).verdict,
    ).toBe("BLOCK");
    expect(
      engine.evaluate({ ...input, action: action("UNKNOWN"), runtimeState: runtime() }).verdict,
    ).toBe("BLOCK");
  });

  it("publishes bounded static destination rules without widening the core defaults", async () => {
    const document = await loadPolicyDocument({
      version: 1,
      navigation: {
        block_private_networks: true,
        max_redirect_hops: 3,
        internal_network_ranges: ["198.18.0.0/15", "fd12:3456::/48"],
      },
    });
    const engine = createPolicyEngine(document);
    expect(engine.destinationRules).toEqual({
      blockPrivateNetworks: true,
      maxRedirectHops: 3,
      internalNetworkRanges: ["198.18.0.0/15", "fd12:3456::/48"],
    });
    expect(Object.isFrozen(engine.destinationRules)).toBe(true);
    expect(Object.isFrozen(engine.destinationRules?.internalNetworkRanges)).toBe(true);
  });

  it("keeps envelope and quarantined state above permissive policy", async () => {
    const document = await loadPolicyDocument({
      version: 1,
      actions: { execute_script: "allow" },
      navigation: { block_private_networks: false },
    });
    const engine = createPolicyEngine(document);
    expect(
      engine.evaluate({
        action: { ...action(), type: "EXECUTE_SCRIPT" },
        envelope: envelope().narrow({ executeScript: false }),
        riskState: "NORMAL",
        runtimeState: runtime(),
      }).verdict,
    ).toBe("BLOCK");
    expect(
      engine.evaluate({
        action: action(),
        envelope: envelope(),
        riskState: "QUARANTINED",
        runtimeState: runtime(),
      }).verdict,
    ).toBe("BLOCK");
  });

  it("validates widening and resolves typed scanner policy only from trusted evidence", async () => {
    const document = await loadPolicyDocument({
      version: 1,
      navigation: { block_private_networks: false },
      actions: { execute_script: "allow" },
      scanners: {
        deterministic: {
          rules: {
            hidden: {
              threshold: 0.6,
              mode: "warn",
              origins: { "https://shop.example": { threshold: 0.9, mode: "block" } },
            },
          },
        },
      },
      suppressions: [{ rule: "hidden", scope: "https://shop.example", justification: "synthetic" }],
    });
    expect(validatePolicy(document)).toMatchObject({
      errors: [],
      warnings: expect.any(Array),
    });
    expect(
      resolveScannerThreshold(document, {
        scannerId: "deterministic",
        ruleId: "hidden",
        origin: "https://shop.example",
      }),
    ).toEqual({ threshold: 0.9, mode: "block" });
    const trusted = runtime({
      scannerEvidence: [
        {
          scannerId: "deterministic",
          ruleId: "hidden",
          origin: "https://shop.example",
          kind: "deterministic",
          outcome: "finding",
          severity: "high",
        },
      ],
    });
    expect(
      resolveScannerSuppression(document, trusted, {
        scannerId: "deterministic",
        ruleId: "hidden",
        origin: "https://shop.example",
      }),
    ).toEqual({ rule: "hidden", scope: "https://shop.example", justification: "synthetic" });
    expect(
      createPolicyEngine(document).evaluate({
        action: action(),
        envelope: envelope(),
        riskState: "NORMAL",
        runtimeState: trusted,
      }).appliedSuppressions,
    ).toEqual([{ rule: "hidden", scope: "https://shop.example", justification: "synthetic" }]);
  });

  it("loads an engine only after document validation", async () => {
    const engine = await loadPolicy({ version: 1 });
    expect(engine.policyHash).toHaveLength(64);
  });

  it("covers deny, stricter navigation, high-risk scanner, and injection branches", async () => {
    const document = await loadPolicyDocument({
      version: 1,
      defaults: { scanner_failure: { high_risk: "block" } },
      actions: { upload: "deny" },
      navigation: { mode: "none" },
      injection: { high_confidence: "block", critical: "quarantine" },
    });
    const engine = createPolicyEngine(document);
    const input = { envelope: envelope(), riskState: "NORMAL" as const };
    expect(
      engine.evaluate({
        ...input,
        action: { ...action(), type: "UPLOAD" },
        runtimeState: runtime(),
      }).verdict,
    ).toBe("BLOCK");
    expect(
      engine.evaluate({ ...input, action: action("NAVIGATE"), runtimeState: runtime() }).verdict,
    ).toBe("BLOCK");
    expect(
      engine.evaluate({
        ...input,
        action: action(),
        runtimeState: runtime({
          scannerEvidence: [
            {
              scannerId: "s",
              ruleId: "r",
              kind: "deterministic",
              outcome: "failure",
              severity: "high",
            },
          ],
        }),
      }).verdict,
    ).toBe("BLOCK");
    expect(
      engine.evaluate({
        ...input,
        action: action(),
        runtimeState: runtime({
          scannerEvidence: [
            {
              scannerId: "injection",
              ruleId: "r",
              kind: "deterministic",
              outcome: "finding",
              severity: "critical",
            },
          ],
        }),
      }).verdict,
    ).toBe("BLOCK");
    expect(validatePolicy(document).errors).toEqual([]);
  });

  it("uses default and absent scanner policy lookups without granting authority", async () => {
    const document = await loadPolicyDocument({
      version: 1,
      scanners: { deterministic: { rules: { rule: { threshold: 0.2 } } } },
    });
    expect(
      resolveScannerThreshold(document, { scannerId: "deterministic", ruleId: "missing" }),
    ).toBeUndefined();
    expect(
      resolveScannerThreshold(document, { scannerId: "deterministic", ruleId: "rule" }),
    ).toEqual({ threshold: 0.2 });
    expect(
      resolveScannerSuppression(document, runtime(), {
        scannerId: "deterministic",
        ruleId: "rule",
      }),
    ).toBeUndefined();
  });

  it("is deterministic for bounded trusted runtime facts", async () => {
    const engine = createPolicyEngine(
      await loadPolicyDocument({ version: 1, budgets: { max_actions: 3, on_exceeded: "block" } }),
    );
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 4 }),
        fc.constantFrom<RiskState>("NORMAL", "RESTRICTED", "QUARANTINED"),
        (actionsUsed, riskState) => {
          const input = {
            action: action(),
            envelope: envelope(),
            riskState,
            runtimeState: runtime({
              budget: { actionsUsed, navigationsUsed: 0, elapsedMs: 0 },
            }),
          };
          expect(engine.evaluate(input)).toEqual(engine.evaluate(input));
        },
      ),
      { numRuns: 100, seed: 20260818 },
    );
  });

  it("has a sub-millisecond median evaluation time on a representative fixture", async () => {
    const engine = createPolicyEngine(
      await loadPolicyDocument({ version: 1, actions: { purchase: "approval" } }),
    );
    const input = {
      action: action("PURCHASE"),
      envelope: envelope(),
      riskState: "NORMAL" as const,
      runtimeState: runtime(),
    };
    for (let index = 0; index < 50; index += 1) engine.evaluate(input);
    const samples = Array.from({ length: 101 }, () => {
      const started = performance.now();
      engine.evaluate(input);
      return performance.now() - started;
    }).sort((left, right) => left - right);
    expect(samples[Math.floor(samples.length / 2)]).toBeLessThan(1);
  });
});
