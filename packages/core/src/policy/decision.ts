import type { AggregateVerdict } from "../contracts/verdict.js";
import type { ReasonCode } from "./reasons.js";

/**
 * Output of the Policy Engine for one authorization question (ARCHITECTURE §4).
 * `policyHash` identifies the policy version for traces/receipts; the engine
 * is pure and synchronous, so identical input yields identical output.
 */
export interface PolicyDecision {
  readonly verdict: AggregateVerdict;
  readonly reasons: readonly ReasonCode[];
  readonly matchedRules: readonly string[];
  readonly requiredApproval?: boolean;
  readonly sanitizations?: readonly string[];
  /** Trace-safe scanner suppression references (ADR-0013), never finding content. */
  readonly appliedSuppressions?: readonly {
    readonly rule: string;
    readonly scope: string;
    readonly justification: string;
  }[];
  readonly policyHash: string;
}
