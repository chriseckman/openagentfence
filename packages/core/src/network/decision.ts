import type { ReasonCode } from "../policy/reasons.js";
import type { EnforcementLevel } from "./capabilities.js";

export const NETWORK_VERDICTS = ["continue", "block", "observe_only_gap"] as const;

export type NetworkVerdict = (typeof NETWORK_VERDICTS)[number];

/**
 * Outcome of the Network Mutation Guard for one mutation (OAF-CORE-017).
 * `continue` and `block` are only meaningful when the surface is `enforced`;
 * `observe_only_gap` is the honest outcome when the adapter cannot block the
 * surface and never implies authorization.
 */
export interface NetworkGuardDecision {
  readonly verdict: NetworkVerdict;
  readonly reasons: readonly ReasonCode[];
  readonly enforcement: EnforcementLevel;
}
