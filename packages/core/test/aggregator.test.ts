import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { riskAggregator, REASON_CODES } from "../src/index.js";
import type { PolicyDecision, ScannerVerdict } from "../src/index.js";
import { mkFinding, mkScanResult } from "./helpers.js";

const HASH = "test-hash";

function allow(overrides: Partial<PolicyDecision> = {}): PolicyDecision {
  return { verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: HASH, ...overrides };
}

describe("risk aggregator fixed precedence", () => {
  it("a deterministic block plus semantic allow yields BLOCK", () => {
    const r = riskAggregator.aggregate({
      scanResults: [
        mkScanResult("det", "deterministic", "block", [
          mkFinding("det-1", "hidden_dom_instruction", { recommendedAction: "block" }),
        ]),
        mkScanResult("sem", "semantic", "allow", [
          mkFinding("sem-1", "injection", { recommendedAction: "allow" }),
        ]),
      ],
      policyDecision: allow(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(r.verdict).toBe("BLOCK");
  });

  it("a semantic block plus deterministic allow yields at most WARN", () => {
    const r = riskAggregator.aggregate({
      scanResults: [
        mkScanResult("det", "deterministic", "allow", []),
        mkScanResult("sem", "semantic", "block", [
          mkFinding("sem-1", "injection", { recommendedAction: "block" }),
        ]),
      ],
      policyDecision: allow(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(r.verdict).toBe("WARN");
    expect(r.decidedBy?.layer).toBe("semantic");
  });

  it("policy BLOCK wins over everything", () => {
    const r = riskAggregator.aggregate({
      scanResults: [],
      policyDecision: allow({
        verdict: "BLOCK",
        reasons: [REASON_CODES.destination_not_allowed],
        matchedRules: ["r1"],
      }),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(r.verdict).toBe("BLOCK");
    expect(r.decidedBy?.layer).toBe("policy");
  });

  it("quarantined session quarantines", () => {
    const r = riskAggregator.aggregate({
      scanResults: [],
      policyDecision: allow(),
      riskState: "QUARANTINED",
      score: 200,
      budgetsExhausted: false,
    });
    expect(r.verdict).toBe("QUARANTINE");
  });

  it("secret sink violation blocks at the secret layer", () => {
    const r = riskAggregator.aggregate({
      scanResults: [],
      policyDecision: allow({ reasons: [REASON_CODES.secret_sink_not_allowed] }),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(r.verdict).toBe("BLOCK");
    expect(r.decidedBy?.layer).toBe("secret");
  });

  it("semantic allow never lowers a deterministic verdict (property)", () => {
    fc.assert(
      fc.property(
        fc.constantFrom<ScannerVerdict>("allow", "warn", "sanitize", "approve", "block"),
        (semanticVerdict) => {
          const r = riskAggregator.aggregate({
            scanResults: [
              mkScanResult("det", "deterministic", "block", [
                mkFinding("det-1", "x", { recommendedAction: "block" }),
              ]),
              mkScanResult("sem", "semantic", semanticVerdict, [
                mkFinding("sem-1", "x", {
                  recommendedAction: semanticVerdict === "block" ? "block" : "allow",
                }),
              ]),
            ],
            policyDecision: allow(),
            riskState: "NORMAL",
            score: 0,
            budgetsExhausted: false,
          });
          expect(r.verdict).toBe("BLOCK");
        },
      ),
    );
  });
});
