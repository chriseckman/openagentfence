import { describe, expect, it, vi } from "vitest";
import fc from "fast-check";
import {
  RedactionRegistry,
  runDetectorRouter,
  riskAggregator,
  type DetectorRouterInput,
  type GuardClassification,
  type GuardExecutionConstraints,
  type GuardModelProvider,
  type ScanResult,
} from "../src/index.js";

const redactor = new RedactionRegistry();
const request = {
  role: "text_injection" as const,
  excerpts: [redactor.redact("untrusted excerpt")],
  taskSummary: redactor.redact("bounded task"),
  localeHints: ["en"],
};

function constraints(
  overrides: Partial<GuardExecutionConstraints> = {},
): GuardExecutionConstraints {
  return {
    signal: new AbortController().signal,
    deadline: Date.now() + 10_000,
    maxInputBytes: 10_000,
    maxOutputBytes: 10_000,
    maxTokens: 4,
    ...overrides,
  };
}

function provider(name: string, classify: GuardModelProvider["classify"]): GuardModelProvider {
  return { name, model: "fixture", makesExternalCalls: false, classify };
}

function deterministic(verdict: "allow" | "block" = "allow"): ScanResult {
  return {
    scanner: "tier0-fixture",
    kind: "deterministic",
    verdict,
    severity: verdict === "block" ? "critical" : "info",
    findings:
      verdict === "block"
        ? [
            {
              id: "tier0:block",
              category: "deterministic_critical",
              title: "Deterministic block",
              description: "Fixture deterministic control blocked.",
              source: { type: "tool" },
              provenance: { trust: "web" },
              evidence: redactor.redact("deterministic block"),
              recommendedAction: "block",
              severity: "critical",
            },
          ]
        : [],
  };
}

function input(overrides: Partial<DetectorRouterInput> = {}): DetectorRouterInput {
  return {
    runTier0: async () => [deterministic()],
    request,
    provenance: { trust: "web" },
    redactor,
    ...overrides,
  };
}

const CLEAN: GuardClassification = {
  promptInjection: false,
  confidence: 0.9,
  categories: [],
  recommendedVerdict: "allow",
};

describe("detector router", () => {
  it("runs Tier 0, Tier 1, and Tier 2 behind fixed barriers", async () => {
    const order: string[] = [];
    const result = await runDetectorRouter(
      input({
        runTier0: async () => {
          order.push("tier0");
          return [deterministic()];
        },
        tier1: {
          provider: provider("tier1", async () => {
            order.push("tier1");
            return CLEAN;
          }),
          constraints: constraints(),
        },
        tier2: {
          provider: provider("tier2", async () => {
            order.push("tier2");
            return CLEAN;
          }),
          constraints: constraints(),
        },
      }),
    );
    expect(order).toEqual(["tier0", "tier1", "tier2"]);
    expect(result.metrics.map(({ tier, status }) => [tier, status])).toEqual([
      ["tier0", "invoked"],
      ["tier1", "invoked"],
      ["tier2", "invoked"],
    ]);
    expect(result.blockingFailure).toBe(false);
  });

  it.each([
    [false, false, ["skipped", "skipped"]],
    [true, false, ["invoked", "skipped"]],
    [false, true, ["skipped", "invoked"]],
    [true, true, ["invoked", "invoked"]],
  ] as const)("routes optional tier slots (%s, %s)", async (withTier1, withTier2, statuses) => {
    const result = await runDetectorRouter(
      input({
        ...(withTier1
          ? { tier1: { provider: provider("t1", async () => CLEAN), constraints: constraints() } }
          : {}),
        ...(withTier2
          ? { tier2: { provider: provider("t2", async () => CLEAN), constraints: constraints() } }
          : {}),
      }),
    );
    expect(result.metrics.slice(1).map((metric) => metric.status)).toEqual(statuses);
  });

  it("short-circuits both semantic tiers after a critical deterministic block", async () => {
    const classify = vi.fn(async () => CLEAN);
    const result = await runDetectorRouter(
      input({
        runTier0: async () => [deterministic("block")],
        tier1: { provider: provider("t1", classify), constraints: constraints() },
        tier2: { provider: provider("t2", classify), constraints: constraints() },
      }),
    );
    expect(classify).not.toHaveBeenCalled();
    expect(result.blockingFailure).toBe(true);
    expect(result.metrics.slice(1).map((metric) => metric.skipReason)).toEqual([
      "deterministic_critical",
      "deterministic_critical",
    ]);
  });

  it("blocks a required malformed tier and does not invoke the next tier", async () => {
    const tier2 = vi.fn(async () => CLEAN);
    const result = await runDetectorRouter(
      input({
        tier1: {
          provider: provider("required", async () => ({ authority: "allow" })),
          constraints: constraints(),
          required: true,
        },
        tier2: { provider: provider("t2", tier2), constraints: constraints() },
      }),
    );
    expect(result.blockingFailure).toBe(true);
    expect(result.results.at(-1)).toMatchObject({ verdict: "block", kind: "semantic" });
    expect(result.metrics.at(-1)).toMatchObject({
      tier: "tier2",
      status: "skipped",
      skipReason: "required_tier_failed",
    });
    expect(tier2).not.toHaveBeenCalled();
  });

  it("keeps an optional provider failure as warning evidence and continues", async () => {
    const tier2 = vi.fn(async () => CLEAN);
    const result = await runDetectorRouter(
      input({
        tier1: {
          provider: provider("optional", async () => {
            throw new Error("synthetic detail must not escape");
          }),
          constraints: constraints(),
        },
        tier2: { provider: provider("t2", tier2), constraints: constraints() },
      }),
    );
    expect(result.blockingFailure).toBe(false);
    expect(result.results[1]).toMatchObject({ verdict: "warn", kind: "semantic" });
    expect(tier2).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(result)).not.toContain("synthetic detail");
  });

  it("reserves one bounded dispatch for each invoked semantic tier", async () => {
    const reserveDispatch = vi.fn(() => true);
    await runDetectorRouter(
      input({
        tier1: {
          provider: provider("t1", async () => CLEAN),
          constraints: constraints({ reserveDispatch }),
        },
        tier2: {
          provider: provider("t2", async () => CLEAN),
          constraints: constraints({ reserveDispatch }),
        },
      }),
    );
    expect(reserveDispatch.mock.calls).toEqual([
      [{ calls: 1, tokens: 4 }],
      [{ calls: 1, tokens: 4 }],
    ]);
  });

  it("never lets arbitrary schema-valid semantic evidence weaken a deterministic decision", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.boolean(),
        fc.double({ min: 0, max: 1, noNaN: true }),
        async (injection, confidence) => {
          const classification: GuardClassification = {
            promptInjection: injection,
            confidence,
            categories: injection ? ["fixture"] : [],
            recommendedVerdict: "allow",
          };
          const result = await runDetectorRouter(
            input({
              runTier0: async () => [deterministic("block")],
              tier2: {
                provider: provider("t2", async () => classification),
                constraints: constraints(),
              },
            }),
          );
          const aggregate = riskAggregator.aggregate({
            scanResults: result.results,
            policyDecision: { verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: "h" },
            riskState: "NORMAL",
            score: 0,
            budgetsExhausted: false,
          });
          expect(aggregate.verdict).toBe("BLOCK");
        },
      ),
    );
  });
});
