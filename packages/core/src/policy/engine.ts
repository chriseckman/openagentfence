import type { CanonicalAction } from "../action/canonical-action.js";
import type { CapabilityEnvelope } from "../envelope/envelope.js";
import type { RiskState } from "../contracts/risk-state.js";
import type { PolicyDecision } from "./decision.js";
import type { ValidatedPolicyRuntimeState } from "./runtime-state.js";
import type { DestinationRules } from "../network/destination.js";

/**
 * Pure, synchronous, I/O-free policy evaluation (ARCHITECTURE §7). The input
 * carries the action, the compiled envelope, and the runtime state; the
 * secure-default engine (OAF-CORE-006) evaluates the envelope only, while the
 * document-driven engine (OAF-POLICY-002) adds static policy.
 */
export interface PolicyEvaluationInput {
  readonly action: CanonicalAction;
  readonly envelope: CapabilityEnvelope;
  readonly riskState: RiskState;
  /** Immutable firewall-owned counters and deterministic scanner summaries (ADR-0013). */
  readonly runtimeState: ValidatedPolicyRuntimeState;
}

export interface PolicyEngine {
  evaluate(input: PolicyEvaluationInput): PolicyDecision;

  /**
   * Stable identifier of the policy in force (ARCHITECTURE §14). Recorded in
   * session-start and decision traces; identical policy yields identical hash.
   */
  readonly policyHash: string;

  /** Optional static destination constraints; absence retains core secure defaults. */
  readonly destinationRules?: DestinationRules;
}
