import type { CapabilityEnvelope } from "../envelope/envelope.js";
import type { RiskState } from "../contracts/risk-state.js";
import type { NetworkMutation } from "./mutation.js";
import type { NetworkGuardDecision } from "./decision.js";

/**
 * Input to the Network Mutation Guard (OAF-CORE-017). The mutation is the
 * untrusted (TB6) observed effect; the envelope and risk state are firewall
 * facts. Evaluation is independent of agent-action authorization.
 */
export interface NetworkGuardInput {
  readonly mutation: NetworkMutation;
  readonly envelope: CapabilityEnvelope;
  readonly riskState: RiskState;
}

/**
 * Framework-neutral Network Mutation Guard contract. Enforcement logic lands
 * with OAF-DATA-007; this is the interface adapters and policy consume.
 */
export interface NetworkGuard {
  evaluate(input: NetworkGuardInput): NetworkGuardDecision;
}
