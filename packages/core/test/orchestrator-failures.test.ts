import { describe, expect, it, vi } from "vitest";
import {
  ScannerRegistry,
  runPhase,
  defineScanner,
  riskAggregator,
  REASON_CODES,
  OpenAgentFence,
} from "../src/index.js";
import type { ScanResult, SecurityContext } from "../src/index.js";
import { fakeAdapter, mkContext, mkAction, mkFinding } from "./helpers.js";

const LIMITS = { maxNodes: 100, maxTextLength: 100, phaseDeadlineMs: 500, scannerConcurrency: 2 };

function allowDecision() {
  return { verdict: "ALLOW" as const, reasons: [], matchedRules: [], policyHash: "h" };
}

describe("orchestrator failure classification (INV-09)", () => {
  it("classifies a thrown exception distinctly from a timeout", async () => {
    const registry = new ScannerRegistry();
    registry.register(
      defineScanner({
        id: "boom",
        phases: ["PERCEPTION"],
        kind: "deterministic",
        scan: async () => {
          throw new Error("boom");
        },
      }),
    );
    const result = await runPhase(registry, "PERCEPTION", mkContext("PERCEPTION"), LIMITS);
    expect(result.failures).toEqual([{ scanner: "boom", kind: "exception" }]);
  });

  it("classifies a malformed result distinctly", async () => {
    const registry = new ScannerRegistry();
    registry.register(
      defineScanner({
        id: "bad",
        phases: ["PERCEPTION"],
        kind: "deterministic",
        // returns a structurally invalid ScanResult
        scan: async () => ({ scanner: "bad", kind: "deterministic" }) as unknown as ScanResult,
      }),
    );
    const result = await runPhase(registry, "PERCEPTION", mkContext("PERCEPTION"), LIMITS);
    expect(result.failures).toEqual([{ scanner: "bad", kind: "malformed" }]);
  });

  it("classifies parent cancellation distinctly", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const registry = new ScannerRegistry();
    registry.register(
      defineScanner({
        id: "slow",
        phases: ["PERCEPTION"],
        kind: "deterministic",
        timeoutMs: 10_000,
        scan: async () => new Promise(() => {}),
      }),
    );
    const ctx = mkContext("PERCEPTION", { kind: "none" }, { signal: controller.signal });
    const promise = runPhase(registry, "PERCEPTION", ctx, LIMITS);
    controller.abort();
    await vi.advanceTimersByTimeAsync(0);
    const result = await promise;
    expect(result.failures).toEqual([{ scanner: "slow", kind: "cancelled" }]);
    vi.useRealTimers();
  });

  it("flags an oversized (truncated) observation", async () => {
    const registry = new ScannerRegistry();
    const ctx = mkContext("PERCEPTION", {
      kind: "observation",
      observation: {
        url: "https://x",
        origin: "https://x",
        frames: [],
        probe: {
          probeVersion: 2,
          truncated: true,
          truncation: {
            nodes: false,
            textBytes: false,
            comments: false,
            metadata: false,
            links: false,
            time: false,
          },
          nodes: [],
          comments: [],
          metadata: { title: "", meta: {}, jsonLd: [], noscript: [] },
          links: [],
        },
        provenance: { trust: "web" },
      },
    });
    const result = await runPhase(registry, "PERCEPTION", ctx, LIMITS);
    expect(result.failures).toEqual([{ scanner: "observation", kind: "oversized" }]);
    expect(result.results[0]).toMatchObject({
      scanner: "observation",
      verdict: "warn",
      findings: [{ category: "scanner_unavailable", recommendedAction: "warn" }],
      metadata: { failureKind: "oversized" },
    });
  });

  it("retains a low-confidence warning while restricting after incomplete perception", async () => {
    const session = new OpenAgentFence({
      adapter: fakeAdapter(),
      scanners: [
        defineScanner({
          id: "bounded-perception",
          phases: ["PERCEPTION"],
          kind: "deterministic",
          scan: async () => ({
            scanner: "bounded-perception",
            kind: "deterministic",
            verdict: "warn",
            severity: "medium",
            findings: [
              mkFinding("bounded", "encoded_payload_limit", {
                severity: "medium",
                recommendedAction: "warn",
              }),
            ],
          }),
        }),
      ],
    }).start({ task: "inspect bounded content" });

    const perception = await session.observe();
    expect(perception.assessment.verdict).toBe("WARN");
    expect(session.riskState).toBe("RESTRICTED");
    const trace = await session.end();
    expect(trace.events).toContainEqual(
      expect.objectContaining({
        kind: "risk_change",
        data: expect.objectContaining({ signal: "hidden_injection" }),
      }),
    );
  });

  it("a timed-out deterministic PRE_ACTION scanner still fails closed", async () => {
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
    const assessment = riskAggregator.aggregate({
      scanResults: result.results,
      policyDecision: allowDecision(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(assessment.verdict).toBe("BLOCK");
    expect(assessment.reasons).toContain(REASON_CODES.scanner_unavailable);
    vi.useRealTimers();
  });

  it("a benign semantic timeout degrades to WARN, not a hard block", async () => {
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
    const assessment = riskAggregator.aggregate({
      scanResults: result.results,
      policyDecision: allowDecision(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(assessment.verdict).toBe("WARN");
    vi.useRealTimers();
  });
});
