import type { NavigationMode } from "../contracts/task-contract.js";
import type { ActionType, ActionTarget } from "../action/canonical-action.js";
import type { ReasonCode } from "../policy/reasons.js";

/**
 * The input an envelope evaluation needs. It is intentionally *not* a
 * `CanonicalAction` — the Action Guard passes a minimal shape so that
 * page-supplied objects can never be mistaken for a validated action.
 */
export interface ActionShape {
  readonly type: ActionType;
  readonly destination?: string;
  readonly target?: ActionTarget;
}

export interface EnvelopeEvaluation {
  readonly allowed: boolean;
  readonly reasons: readonly ReasonCode[];
}

export interface ResolvedCapabilities {
  readonly navigation: NavigationMode;
  readonly downloads: boolean;
  readonly uploads: boolean;
  readonly purchases: boolean;
  readonly messaging: boolean;
  readonly destructiveActions: boolean;
  readonly credentials: boolean;
  readonly executeScript: boolean;
  readonly privateNetwork: boolean;
  readonly externalCommunication: boolean;
}

/**
 * The compiled, enforceable result of a validated `TaskContract` constrained
 * by secure defaults (ARCHITECTURE §4, ADR-0009). Answers the session's
 * maximum possible authority without a model. It can only shrink during a
 * session; it is never compiled from a policy document, profile, provider
 * configuration, or credential.
 */
export interface CapabilityEnvelope extends ResolvedCapabilities {
  readonly task: string;
  readonly allowedOrigins: readonly string[];
  readonly blockedOrigins: readonly string[];
  evaluate(action: ActionShape): EnvelopeEvaluation;
  narrow(patch: EnvelopeNarrowing): CapabilityEnvelope;
}

export interface EnvelopeNarrowing {
  readonly navigation?: NavigationMode;
  readonly downloads?: boolean;
  readonly uploads?: boolean;
  readonly purchases?: boolean;
  readonly messaging?: boolean;
  readonly destructiveActions?: boolean;
  readonly credentials?: boolean;
  readonly executeScript?: boolean;
  readonly privateNetwork?: boolean;
  readonly externalCommunication?: boolean;
  readonly allowedOrigins?: readonly string[];
}
