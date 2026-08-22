import type { Finding } from "../contracts/finding.js";
import type { SessionRisk } from "../contracts/risk-state.js";
import type { AggregateVerdict } from "../contracts/verdict.js";
import type { CanonicalAction } from "../action/canonical-action.js";
import type { EvidenceReference } from "../trace/events.js";
import type { ApprovalRequest } from "./approval.js";

export interface SessionDecision {
  readonly verdict: AggregateVerdict;
  readonly reasons: readonly string[];
  readonly action: CanonicalAction;
  /** Redacted, reproducible evidence references for non-ALLOW decisions. */
  readonly evidence?: readonly EvidenceReference[];
  /** Policy-rule identifiers that produced this decision (ADR-0013). */
  readonly matchedRules?: readonly string[];
  /** Trace-safe suppression references; never finding evidence or page content. */
  readonly appliedSuppressions?: readonly {
    readonly rule: string;
    readonly scope: string;
    readonly justification: string;
  }[];
}

export interface SessionEvents {
  finding: Finding;
  decision: SessionDecision;
  riskChanged: SessionRisk;
  approvalRequired: ApprovalRequest;
}
