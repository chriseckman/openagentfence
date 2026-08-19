import { hash } from "../trace/redact.js";
import { REASON_CODES } from "./reasons.js";
import type { PolicyEngine, PolicyEvaluationInput } from "./engine.js";
import type { PolicyDecision } from "./decision.js";

/** `policyHash` for the secure-default engine, a constant derived from its version. */
export const SECURE_DEFAULT_POLICY_HASH = hash("openagentfence-secure-default-engine-v1");

/**
 * The built-in engine used when no policy is configured (ARCHITECTURE §3). It
 * evaluates the envelope defaults only — no clocks, no randomness, no I/O —
 * so it is deterministic and replayable.
 */
export const secureDefaultPolicyEngine: PolicyEngine = {
  policyHash: SECURE_DEFAULT_POLICY_HASH,

  evaluate(input: PolicyEvaluationInput): PolicyDecision {
    const evaluation = input.envelope.evaluate(input.action);
    if (!evaluation.allowed) {
      return {
        verdict: "BLOCK",
        reasons: evaluation.reasons,
        matchedRules: ["secure-default-envelope"],
        policyHash: SECURE_DEFAULT_POLICY_HASH,
      };
    }
    if (input.riskState === "QUARANTINED") {
      return {
        verdict: "BLOCK",
        reasons: [REASON_CODES.session_restricted],
        matchedRules: ["secure-default-session"],
        policyHash: SECURE_DEFAULT_POLICY_HASH,
      };
    }
    return {
      verdict: "ALLOW",
      reasons: [],
      matchedRules: [],
      policyHash: SECURE_DEFAULT_POLICY_HASH,
    };
  },
};
