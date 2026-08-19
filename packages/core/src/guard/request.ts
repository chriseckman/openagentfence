import type { RedactedEvidence } from "../trace/redact.js";
import type { GuardRole } from "./roles.js";

export interface GuardBudget {
  readonly maxTokens?: number;
}

/**
 * A classification request can only be built from `RedactedEvidence` (type
 * enforced): raw page text or secret values cannot reach a provider (TB3,
 * INV-05). Budget hooks are declared here and consumed by the providers
 * package and the budget engine.
 */
export interface GuardClassificationRequest {
  readonly role: GuardRole;
  readonly excerpts: readonly RedactedEvidence[];
  readonly taskSummary: RedactedEvidence;
  readonly localeHints: readonly string[];
  readonly budget?: GuardBudget;
}
