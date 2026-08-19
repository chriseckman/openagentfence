import type { AggregateVerdict } from "./verdict.js";
import type { Finding } from "./finding.js";
import type { SessionRisk } from "./risk-state.js";

/**
 * Result of risk aggregation with fixed precedence (PRD §15, ARCHITECTURE §4).
 * Findings are bucketed by the kind of scanner that produced them; `decidedBy`
 * records the layer and rule/finding that produced the final verdict so
 * `openagentfence explain` can render the reason chain.
 */
export interface RiskAssessment {
  readonly deterministic: readonly Finding[];
  readonly semantic: readonly Finding[];
  readonly provenance: readonly Finding[];
  readonly session: SessionRisk;
  readonly verdict: AggregateVerdict;
  readonly reasons: readonly string[];
  readonly decidedBy: {
    readonly layer:
      "critical" | "policy" | "secret" | "session" | "semantic" | "heuristic" | "default";
    readonly ruleOrFindingId: string;
  } | null;
}
