export const RISK_STATES = ["NORMAL", "RESTRICTED", "READ_ONLY", "QUARANTINED"] as const;

export type RiskState = (typeof RISK_STATES)[number];

/** Monotonic risk-state ordering: later states are strictly more restrictive. */
export const RISK_STATE_ORDER: readonly RiskState[] = RISK_STATES;

/** Return the more restrictive of two risk states. */
export function maxRiskState(a: RiskState, b: RiskState): RiskState {
  const ai = RISK_STATE_ORDER.indexOf(a);
  const bi = RISK_STATE_ORDER.indexOf(b);
  return bi > ai ? b : a;
}

/** The risk engine's score is an opaque monotonic number; thresholds map it to states. */
export interface SessionRisk {
  readonly state: RiskState;
  readonly score: number;
}
