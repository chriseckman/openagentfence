import { describe, expect, it, vi } from "vitest";
import {
  ScannerRegistry,
  runPhase,
  defineScanner,
  REASON_CODES,
  riskAggregator,
} from "../src/index.js";
import type { SecurityContext } from "../src/index.js";
import { mkContext, mkAction } from "./helpers.js";

const LIMITS = { maxNodes: 100, maxTextLength: 100, phaseDeadlineMs: 500, scannerConcurrency: 2 };

function allowDecision() {
  return { verdict: "ALLOW" as const, reasons: [], matchedRules: [], policyHash: "h" };
}

describe("orchestrator timeouts and fail-closed", () => {
  it("records a never-resolving scanner as timed_out, never allow", async () => {
    vi.useFakeTimers();
    const registry = new ScannerRegistry();
    registry.register(
      defineScanner({
        id: "hang",
        phases: ["PERCEPTION"],
        kind: "deterministic",
        timeoutMs: 50,
        scan: async () => new Promise(() => {}),
      }),
    );
    const promise = runPhase(registry, "PERCEPTION", mkContext("PERCEPTION"), LIMITS);
    await vi.advanceTimersByTimeAsync(60);
    const result = await promise;
    expect(result.failures.map((f) => f.scanner)).toContain("hang");
    expect(result.results[0]?.timedOut).toBe(true);
    vi.useRealTimers();
  });

  it("a PRE_ACTION deterministic timeout on a high-impact action produces BLOCK", async () => {
    vi.useFakeTimers();
    const registry = new ScannerRegistry();
    registry.register(
      defineScanner({
        id: "precheck",
        phases: ["PRE_ACTION"],
        kind: "deterministic",
        timeoutMs: 50,
        scan: async () => new Promise(() => {}),
      }),
    );
    const ctx: SecurityContext = mkContext("PRE_ACTION", {
      kind: "proposedAction",
      action: mkAction("SUBMIT"),
    });
    const promise = runPhase(registry, "PRE_ACTION", ctx, LIMITS);
    await vi.advanceTimersByTimeAsync(60);
    const result = await promise;
    const block = result.results[0];
    expect(block?.verdict).toBe("block");
    vi.useRealTimers();
  });

  it("a PERCEPTION semantic timeout on a benign page produces WARN with scanner_unavailable", async () => {
    vi.useFakeTimers();
    const registry = new ScannerRegistry();
    registry.register(
      defineScanner({
        id: "sem",
        phases: ["PERCEPTION"],
        kind: "semantic",
        timeoutMs: 50,
        scan: async () => new Promise(() => {}),
      }),
    );
    const promise = runPhase(registry, "PERCEPTION", mkContext("PERCEPTION"), LIMITS);
    await vi.advanceTimersByTimeAsync(60);
    const result = await promise;
    const agg = riskAggregator.aggregate({
      scanResults: result.results,
      policyDecision: allowDecision(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(agg.verdict).toBe("WARN");
    expect(agg.reasons).toContain(REASON_CODES.scanner_unavailable);
    vi.useRealTimers();
  });

  it("runs deterministic scanners before semantic scanners", async () => {
    const order: string[] = [];
    const registry = new ScannerRegistry();
    registry.register(
      defineScanner({
        id: "sem",
        phases: ["PERCEPTION"],
        kind: "semantic",
        scan: async () => {
          order.push("sem");
          return {
            scanner: "sem",
            kind: "semantic" as const,
            verdict: "allow" as const,
            severity: "low" as const,
            findings: [],
          };
        },
      }),
    );
    registry.register(
      defineScanner({
        id: "det",
        phases: ["PERCEPTION"],
        kind: "deterministic",
        scan: async () => {
          order.push("det");
          return {
            scanner: "det",
            kind: "deterministic" as const,
            verdict: "allow" as const,
            severity: "low" as const,
            findings: [],
          };
        },
      }),
    );
    await runPhase(registry, "PERCEPTION", mkContext("PERCEPTION"), LIMITS);
    expect(order).toEqual(["det", "sem"]);
  });

  it("runs Tier 1 before Tier 2 regardless of registration priority", async () => {
    const order: string[] = [];
    const registry = new ScannerRegistry();
    for (const [id, tier, priority] of [
      ["tier2", "tier2", -100],
      ["tier1", "tier1", 100],
    ] as const) {
      registry.register(
        defineScanner({
          id,
          phases: ["PERCEPTION"],
          kind: "semantic",
          tier,
          priority,
          scan: async () => {
            order.push(id);
            return {
              scanner: id,
              kind: "semantic",
              verdict: "allow",
              severity: "info",
              findings: [],
            };
          },
        }),
      );
    }
    const result = await runPhase(registry, "PERCEPTION", mkContext("PERCEPTION"), LIMITS);
    expect(order).toEqual(["tier1", "tier2"]);
    expect(result.tierMetrics).toEqual([
      { tier: "tier0", status: "invoked", scannerCount: 0 },
      { tier: "tier1", status: "invoked", scannerCount: 1 },
      { tier: "tier2", status: "invoked", scannerCount: 1 },
    ]);
  });

  it("does not invoke semantic scanners after a critical Tier 0 result", async () => {
    const semantic = vi.fn(async () => ({
      scanner: "semantic",
      kind: "semantic" as const,
      verdict: "allow" as const,
      severity: "info" as const,
      findings: [],
    }));
    const registry = new ScannerRegistry();
    registry.register(
      defineScanner({
        id: "critical",
        phases: ["PERCEPTION"],
        kind: "deterministic",
        scan: async () => ({
          scanner: "critical",
          kind: "deterministic",
          verdict: "block",
          severity: "critical",
          findings: [],
        }),
      }),
    );
    registry.register(
      defineScanner({
        id: "semantic",
        phases: ["PERCEPTION"],
        kind: "semantic",
        tier: "tier2",
        scan: semantic,
      }),
    );
    const result = await runPhase(registry, "PERCEPTION", mkContext("PERCEPTION"), LIMITS);
    expect(semantic).not.toHaveBeenCalled();
    expect(result.tierMetrics[2]).toMatchObject({
      status: "skipped",
      skipReason: "deterministic_critical",
    });
  });
});
