import { maxRiskState, type RiskState, type SessionRisk } from "../contracts/risk-state.js";

/** Firewall-owned risk signals; page content contributes evidence, never authority. */
export type RiskSignal =
  | "hidden_injection"
  | "cross_origin_redirect"
  | "secret_requested"
  | "unrelated_tab"
  | "high_confidence_injection"
  | "critical_finding";

export interface RiskPolicy {
  readonly hiddenInjectionWeight: number;
  readonly crossOriginRedirectWeight: number;
  readonly secretRequestedWeight: number;
  readonly unrelatedTabWeight: number;
  readonly restrictedAt: number;
  readonly readOnlyAt: number;
  readonly quarantinedAt: number;
}

/** Exact v0.1 defaults from PRD §13.11. */
export const DEFAULT_RISK_POLICY: RiskPolicy = Object.freeze({
  hiddenInjectionWeight: 40,
  crossOriginRedirectWeight: 20,
  secretRequestedWeight: 50,
  unrelatedTabWeight: 30,
  restrictedAt: 40,
  readOnlyAt: 80,
  quarantinedAt: 120,
});

export interface RiskTransition {
  readonly previous: SessionRisk;
  readonly current: SessionRisk;
  readonly signal: RiskSignal;
}

/** Apply a non-decreasing risk transition with forced P0 injection states. */
export function applyRiskSignal(
  current: SessionRisk,
  signal: RiskSignal,
  policy: RiskPolicy = DEFAULT_RISK_POLICY,
): RiskTransition {
  const score = current.score + weightFor(signal, policy);
  const forced =
    signal === "critical_finding"
      ? "QUARANTINED"
      : signal === "high_confidence_injection"
        ? "RESTRICTED"
        : stateForScore(score, policy);
  return {
    previous: current,
    current: { state: maxRiskState(current.state, forced), score: Math.max(current.score, score) },
    signal,
  };
}

/** Map a score to the exact monotonic v0.1 risk state. */
export function stateForScore(score: number, policy: RiskPolicy = DEFAULT_RISK_POLICY): RiskState {
  if (score >= policy.quarantinedAt) return "QUARANTINED";
  if (score >= policy.readOnlyAt) return "READ_ONLY";
  if (score >= policy.restrictedAt) return "RESTRICTED";
  return "NORMAL";
}

function weightFor(signal: RiskSignal, policy: RiskPolicy): number {
  switch (signal) {
    case "hidden_injection":
    case "high_confidence_injection":
      return policy.hiddenInjectionWeight;
    case "cross_origin_redirect":
      return policy.crossOriginRedirectWeight;
    case "secret_requested":
      return policy.secretRequestedWeight;
    case "unrelated_tab":
      return policy.unrelatedTabWeight;
    case "critical_finding":
      return 0;
  }
}
