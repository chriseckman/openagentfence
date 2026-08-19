import type { ScanResult } from "../contracts/scan-result.js";
import type { Finding } from "../contracts/finding.js";
import type { RiskAssessment } from "../contracts/risk-assessment.js";
import type { SessionRisk, RiskState } from "../contracts/risk-state.js";
import type { PolicyDecision } from "../policy/decision.js";
import type { AggregateVerdict } from "../contracts/verdict.js";
import { REASON_CODES } from "../policy/reasons.js";

/**
 * Fixed precedence (PRD §15, ADR-0003): a critical deterministic block outranks
 * explicit application policy, which outranks secret/data-flow blocks, then
 * session restriction, then semantic detection, then warning-only heuristics.
 * A semantic "allow" can never remove a deterministic block, and a semantic
 * "block" is evidence only (at most WARN on a low-risk read unless policy
 * elevates).
 */
export interface RiskAggregationInput {
  readonly scanResults: readonly ScanResult[];
  readonly policyDecision: PolicyDecision;
  readonly riskState: RiskState;
  readonly score: number;
  readonly budgetsExhausted: boolean;
  /**
   * The Action Guard already evaluated the exact restricted-state action set.
   * This is firewall-owned evidence, never an adapter/model assertion.
   */
  readonly restrictedActionAllowed?: boolean;
}

export interface RiskAggregator {
  aggregate(input: RiskAggregationInput): RiskAssessment;
}

function isProvenanceFinding(finding: Finding): boolean {
  return (
    finding.category.startsWith("provenance") ||
    finding.category === "instruction_provenance_untrusted"
  );
}

function isSecretFinding(finding: Finding): boolean {
  return (
    finding.category.startsWith("secret") ||
    finding.category.includes("exfiltration") ||
    finding.recommendedAction === "block"
  );
}

export function createRiskAggregator(): RiskAggregator {
  return { aggregate };
}

export const riskAggregator: RiskAggregator = createRiskAggregator();

function aggregate(input: RiskAggregationInput): RiskAssessment {
  const { scanResults, policyDecision, riskState, score } = input;

  const deterministic: Finding[] = [];
  const semantic: Finding[] = [];
  const provenance: Finding[] = [];
  for (const result of scanResults) {
    for (const finding of result.findings) {
      if (isProvenanceFinding(finding)) {
        provenance.push(finding);
      } else if (result.kind === "semantic") {
        semantic.push(finding);
      } else {
        deterministic.push(finding);
      }
    }
  }

  // Layer 1: critical deterministic block.
  const criticalBlock = deterministic.find((f) => f.recommendedAction === "block");
  if (criticalBlock !== undefined) {
    const reason =
      criticalBlock.category === "scanner_unavailable"
        ? REASON_CODES.scanner_unavailable
        : REASON_CODES.capability_denied;
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      "BLOCK",
      mergeReasons(policyDecision.reasons, [reason]),
      {
        layer: "critical",
        ruleOrFindingId: criticalBlock.id,
      },
    );
  }

  // Layer 2: explicit application policy.
  if (policyDecision.verdict === "BLOCK" || policyDecision.verdict === "REQUIRE_APPROVAL") {
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      policyDecision.verdict,
      policyDecision.reasons,
      {
        layer: "policy",
        ruleOrFindingId: policyDecision.matchedRules[0] ?? policyDecision.reasons[0] ?? "policy",
      },
    );
  }

  // Layer 3: secret/data-flow block.
  if (policyDecision.reasons.includes(REASON_CODES.secret_sink_not_allowed)) {
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      "BLOCK",
      [REASON_CODES.secret_sink_not_allowed],
      {
        layer: "secret",
        ruleOrFindingId: "secret_sink_not_allowed",
      },
    );
  }
  const secretFinding = deterministic.find(isSecretFinding);
  if (secretFinding !== undefined) {
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      "BLOCK",
      [REASON_CODES.secret_sink_not_allowed],
      {
        layer: "secret",
        ruleOrFindingId: secretFinding.id,
      },
    );
  }

  // Layer 4: session restriction.
  if (riskState === "QUARANTINED") {
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      "QUARANTINE",
      [REASON_CODES.session_restricted],
      {
        layer: "session",
        ruleOrFindingId: "session_risk",
      },
    );
  }
  if (
    (riskState === "RESTRICTED" || riskState === "READ_ONLY") &&
    input.restrictedActionAllowed !== true
  ) {
    if (policyDecision.verdict === "ALLOW") {
      return assessment(
        deterministic,
        semantic,
        provenance,
        score,
        riskState,
        "RESTRICT",
        [REASON_CODES.session_restricted],
        {
          layer: "session",
          ruleOrFindingId: "session_risk",
        },
      );
    }
  }

  // Layer 5: deterministic approval recommendation (stronger than semantic).
  const detApprove = deterministic.find((f) => f.recommendedAction === "approve");
  if (detApprove !== undefined) {
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      "REQUIRE_APPROVAL",
      [REASON_CODES.approval_required],
      {
        layer: "critical",
        ruleOrFindingId: detApprove.id,
      },
    );
  }

  // Layer 5b: semantic detection (evidence only).
  const semanticApprove = semantic.find((f) => f.recommendedAction === "approve");
  const semanticBlock = semantic.find((f) => f.recommendedAction === "block");
  if (semanticApprove !== undefined) {
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      "REQUIRE_APPROVAL",
      [REASON_CODES.session_contains_high_confidence_prompt_injection],
      {
        layer: "semantic",
        ruleOrFindingId: semanticApprove.id,
      },
    );
  }
  if (semanticBlock !== undefined) {
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      "WARN",
      [REASON_CODES.session_contains_high_confidence_prompt_injection],
      {
        layer: "semantic",
        ruleOrFindingId: semanticBlock.id,
      },
    );
  }

  // Layer 6: warning-only heuristics (deterministic and semantic advisories).
  const warning = [...deterministic, ...semantic].find(
    (f) => f.recommendedAction === "warn" || f.recommendedAction === "sanitize",
  );
  if (warning !== undefined) {
    const reasons =
      warning.category === "scanner_unavailable" ? [REASON_CODES.scanner_unavailable] : [];
    return assessment(deterministic, semantic, provenance, score, riskState, "WARN", reasons, {
      layer: "heuristic",
      ruleOrFindingId: warning.id,
    });
  }

  if (input.budgetsExhausted) {
    return assessment(
      deterministic,
      semantic,
      provenance,
      score,
      riskState,
      "WARN",
      [REASON_CODES.budget_exceeded],
      {
        layer: "session",
        ruleOrFindingId: "budgets",
      },
    );
  }

  const sanitized = scanResults.some((r) => r.sanitized !== undefined);
  const verdict: AggregateVerdict = sanitized ? "ALLOW_SANITIZED" : "ALLOW";
  return assessment(deterministic, semantic, provenance, score, riskState, verdict, [], null);
}

function mergeReasons(first: readonly string[], second: readonly string[]): readonly string[] {
  return [...new Set([...first, ...second])];
}

function assessment(
  deterministic: readonly Finding[],
  semantic: readonly Finding[],
  provenance: readonly Finding[],
  score: number,
  riskState: RiskState,
  verdict: AggregateVerdict,
  reasons: readonly string[],
  decidedBy: RiskAssessment["decidedBy"],
): RiskAssessment {
  const session: SessionRisk = { state: riskState, score };
  return {
    deterministic,
    semantic,
    provenance,
    session,
    verdict,
    reasons,
    decidedBy,
  };
}
