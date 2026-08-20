import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { riskAggregator, REASON_CODES } from "../src/index.js";
import type {
  AggregateVerdict,
  PolicyDecision,
  ReasonCode,
  RiskState,
  ScannerVerdict,
  ScanResult,
} from "../src/index.js";
import { mkFinding, mkScanResult } from "./helpers.js";

interface Row {
  readonly name: string;
  readonly det?: ScannerVerdict;
  readonly detCategory?: string;
  readonly sem?: ScannerVerdict;
  readonly policy?: AggregateVerdict;
  readonly policyReasons?: readonly ReasonCode[];
  readonly risk?: RiskState;
  readonly budgets?: boolean;
  readonly sanitized?: boolean;
  readonly expected: AggregateVerdict;
}

const ROWS: readonly Row[] = [
  { name: "clean read", expected: "ALLOW" },
  { name: "clean read with sanitization", sanitized: true, expected: "ALLOW_SANITIZED" },
  { name: "budgets exhausted", budgets: true, expected: "WARN" },
  { name: "quarantined session", risk: "QUARANTINED", expected: "QUARANTINE" },
  { name: "restricted session allows nothing new", risk: "RESTRICTED", expected: "RESTRICT" },
  { name: "read-only session", risk: "READ_ONLY", expected: "RESTRICT" },
  { name: "policy block", policy: "BLOCK", expected: "BLOCK" },
  { name: "policy require approval", policy: "REQUIRE_APPROVAL", expected: "REQUIRE_APPROVAL" },
  {
    name: "policy secret sink reason",
    policy: "ALLOW",
    policyReasons: [REASON_CODES.secret_sink_not_allowed],
    expected: "BLOCK",
  },
  { name: "det block", det: "block", expected: "BLOCK" },
  { name: "det approve", det: "approve", expected: "REQUIRE_APPROVAL" },
  { name: "det warn", det: "warn", expected: "WARN" },
  { name: "det sanitize finding", det: "sanitize", expected: "WARN" },
  { name: "det secret category", det: "warn", detCategory: "secret_leak", expected: "BLOCK" },
  { name: "det block beats sem allow", det: "block", sem: "allow", expected: "BLOCK" },
  { name: "det block beats sem block", det: "block", sem: "block", expected: "BLOCK" },
  { name: "det block beats sem approve", det: "block", sem: "approve", expected: "BLOCK" },
  {
    name: "det approve beats sem block",
    det: "approve",
    sem: "block",
    expected: "REQUIRE_APPROVAL",
  },
  { name: "det warn with sem block", det: "warn", sem: "block", expected: "WARN" },
  { name: "sem block on clean read", sem: "block", expected: "WARN" },
  { name: "sem approve on clean read", sem: "approve", expected: "REQUIRE_APPROVAL" },
  { name: "sem warn on clean read", sem: "warn", expected: "WARN" },
  { name: "sem allow has no effect", sem: "allow", expected: "ALLOW" },
  { name: "policy block over det warn", det: "warn", policy: "BLOCK", expected: "BLOCK" },
  {
    name: "policy require approval over sem block",
    sem: "block",
    policy: "REQUIRE_APPROVAL",
    expected: "REQUIRE_APPROVAL",
  },
  { name: "policy block over restricted", risk: "RESTRICTED", policy: "BLOCK", expected: "BLOCK" },
  { name: "det block in quarantined", det: "block", risk: "QUARANTINED", expected: "BLOCK" },
  { name: "sem block in quarantined", sem: "block", risk: "QUARANTINED", expected: "QUARANTINE" },
  { name: "sem approve in restricted", sem: "approve", risk: "RESTRICTED", expected: "RESTRICT" },
  { name: "det warn in restricted", det: "warn", risk: "RESTRICTED", expected: "RESTRICT" },
  {
    name: "secret reason in quarantined",
    policy: "ALLOW",
    policyReasons: [REASON_CODES.secret_sink_not_allowed],
    risk: "QUARANTINED",
    expected: "BLOCK",
  },
  { name: "det warn with sanitization", det: "warn", sanitized: true, expected: "WARN" },
  {
    name: "sem allow with sanitization",
    sem: "allow",
    sanitized: true,
    expected: "ALLOW_SANITIZED",
  },
  { name: "det approve with budgets", det: "approve", budgets: true, expected: "REQUIRE_APPROVAL" },
  { name: "sem block with budgets", sem: "block", budgets: true, expected: "WARN" },
  { name: "det block with budgets", det: "block", budgets: true, expected: "BLOCK" },
  {
    name: "det secret with sem allow",
    det: "warn",
    detCategory: "secret_leak",
    sem: "allow",
    expected: "BLOCK",
  },
  { name: "policy block with det approve", det: "approve", policy: "BLOCK", expected: "BLOCK" },
  {
    name: "det approve with sem approve",
    det: "approve",
    sem: "approve",
    expected: "REQUIRE_APPROVAL",
  },
  { name: "sem approve with sem block", sem: "approve", expected: "REQUIRE_APPROVAL" },
  { name: "restricted with det approve", det: "approve", risk: "RESTRICTED", expected: "RESTRICT" },
  { name: "read-only with policy block", risk: "READ_ONLY", policy: "BLOCK", expected: "BLOCK" },
  { name: "det warn with det block", det: "block", expected: "BLOCK" },
  { name: "clean read in read-only", risk: "READ_ONLY", expected: "RESTRICT" },
  { name: "sem block in read-only", sem: "block", risk: "READ_ONLY", expected: "RESTRICT" },
];

function run(row: Row) {
  const results: ScanResult[] = [];
  if (row.det !== undefined) {
    const category = row.detCategory ?? "hidden_dom_instruction";
    results.push(
      mkScanResult(
        "det",
        "deterministic",
        row.det,
        [mkFinding("d", category, { recommendedAction: row.det })],
        {
          ...(row.sanitized ? { sanitized: { value: "safe", provenance: { trust: "web" } } } : {}),
        },
      ),
    );
  } else if (row.sanitized) {
    results.push(
      mkScanResult("det", "deterministic", "sanitize", [], {
        sanitized: { value: "safe", provenance: { trust: "web" } },
      }),
    );
  }
  if (row.sem !== undefined) {
    results.push(
      mkScanResult("sem", "semantic", row.sem, [
        mkFinding("s", "injection", { recommendedAction: row.sem }),
      ]),
    );
  }
  const policyDecision: PolicyDecision = {
    verdict: row.policy ?? "ALLOW",
    reasons: row.policyReasons ?? [],
    matchedRules: [],
    policyHash: "h",
  };
  return riskAggregator.aggregate({
    scanResults: results,
    policyDecision,
    riskState: row.risk ?? "NORMAL",
    score: 0,
    budgetsExhausted: row.budgets ?? false,
  });
}

describe("fixed-precedence table (40+ named rows)", () => {
  it.each(ROWS.map((r) => [r.name, r] as const))("%s", (_name, row) => {
    const assessment = run(row);
    expect(assessment.verdict, `${row.name} -> ${assessment.verdict}`).toBe(row.expected);
  });
});

describe("aggregation properties", () => {
  const scanResultsFor = (det: ScannerVerdict, sem: ScannerVerdict): ScanResult[] => [
    mkScanResult("det", "deterministic", det, [mkFinding("d", "x", { recommendedAction: det })]),
    mkScanResult("sem", "semantic", sem, [mkFinding("s", "x", { recommendedAction: sem })]),
  ];

  it("deterministic block monotonicity (semantic cannot lower it)", () => {
    fc.assert(
      fc.property(
        fc.constantFrom<ScannerVerdict>("allow", "warn", "sanitize", "approve", "block"),
        (sem) => {
          const a = riskAggregator.aggregate({
            scanResults: scanResultsFor("block", sem),
            policyDecision: { verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: "h" },
            riskState: "NORMAL",
            score: 0,
            budgetsExhausted: false,
          });
          expect(a.verdict).toBe("BLOCK");
        },
      ),
    );
  });

  it("is idempotent and order-independent", () => {
    fc.assert(
      fc.property(
        fc.constantFrom<ScannerVerdict>("warn", "block", "allow"),
        fc.constantFrom<ScannerVerdict>("warn", "approve", "allow"),
        (det, sem) => {
          const base = {
            policyDecision: {
              verdict: "ALLOW" as const,
              reasons: [] as const,
              matchedRules: [] as const,
              policyHash: "h",
            },
            riskState: "NORMAL" as const,
            score: 0,
            budgetsExhausted: false,
          };
          const forward = riskAggregator.aggregate({
            scanResults: scanResultsFor(det, sem),
            ...base,
          });
          const reversed = riskAggregator.aggregate({
            scanResults: [...scanResultsFor(det, sem)].reverse(),
            ...base,
          });
          expect(reversed.verdict).toBe(forward.verdict);
          const again = riskAggregator.aggregate({
            scanResults: scanResultsFor(det, sem),
            ...base,
          });
          expect(again.verdict).toBe(forward.verdict);
        },
      ),
    );
  });
});
