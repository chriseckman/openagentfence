import type { SecurityPhase } from "../contracts/phase.js";
import type { TaskContract } from "../contracts/task-contract.js";
import type { RiskState } from "../contracts/risk-state.js";
import type { DataProvenance } from "../contracts/provenance.js";
import type { RedactionRegistry } from "../trace/redact.js";
import type { PageObservation } from "../adapter/observation.js";
import type { CanonicalAction } from "../action/canonical-action.js";
import type { PostActionObservation } from "../action/post-action.js";
import type { SecretHandle } from "../secrets/handle-codec.js";
import type { ScannerPermission } from "./manifest.js";
import { detectHandles } from "../secrets/handle-codec.js";

export interface ModelOutput {
  readonly content: string;
  readonly provenance: DataProvenance;
}

export type PhasePayload =
  | { readonly kind: "observation"; readonly observation: PageObservation }
  | { readonly kind: "proposedAction"; readonly action: CanonicalAction }
  | { readonly kind: "postAction"; readonly observation: PostActionObservation }
  | { readonly kind: "modelOutput"; readonly output: ModelOutput }
  | { readonly kind: "memoryCandidate"; readonly candidate: unknown }
  | { readonly kind: "egressPayload"; readonly payload: unknown }
  | { readonly kind: "none" };

/**
 * Immutable per-invocation input to a scanner (ARCHITECTURE §4). Carries only
 * what the phase needs plus session references, a deadline, and an
 * `AbortSignal`. Never contains raw secret values.
 */
export interface SecurityContext {
  readonly phase: SecurityPhase;
  readonly sessionId: string;
  readonly taskContract: TaskContract;
  readonly envelope: import("../envelope/envelope.js").CapabilityEnvelope;
  readonly riskState: RiskState;
  readonly payload: PhasePayload;
  readonly provenance: DataProvenance;
  readonly redactor: RedactionRegistry;
  readonly deadline: number;
  readonly signal: AbortSignal;
}

/**
 * Least-privilege view presented to plugin scanners (INV-15). Only fields
 * selected by manifest permissions are populated; raw secrets are never
 * present.
 */
export interface ScopedContextView {
  readonly phase: SecurityPhase;
  readonly sessionId: string;
  readonly riskState: RiskState;
  readonly deadline: number;
  readonly signal: AbortSignal;
  readonly observation?: Readonly<Record<string, unknown>>;
  readonly action?: Readonly<Record<string, unknown>>;
  readonly handles?: readonly SecretHandle[];
}

/**
 * Build the scoped view for a plugin scanner from its manifest permissions.
 * Built-in scanners receive the full `SecurityContext`; plugin scanners receive
 * only this view.
 */
export function buildScopedView(
  ctx: SecurityContext,
  permissions: readonly ScannerPermission[],
): ScopedContextView {
  const granted = new Set(permissions);
  const payload = ctx.payload;

  let observation: Readonly<Record<string, unknown>> | undefined;
  let action: Readonly<Record<string, unknown>> | undefined;
  let handles: readonly SecretHandle[] | undefined;

  if (payload.kind === "observation") {
    const hasPage =
      granted.has("page:visible_text") ||
      granted.has("page:hidden_text") ||
      granted.has("page:redacted_text");
    const hasScreenshot = granted.has("page:screenshot");
    if (hasPage || hasScreenshot) {
      const obs: Record<string, unknown> = {
        url: payload.observation.url,
        origin: payload.observation.origin,
      };
      if (hasPage) {
        const snapshot = payload.observation.ariaSnapshot;
        if (snapshot !== undefined) {
          obs["ariaSnapshot"] = ctx.redactor.redact(snapshot);
        }
      }
      if (hasScreenshot && payload.observation.screenshot !== undefined) {
        obs["screenshot"] = payload.observation.screenshot;
      }
      observation = obs;
    }
  } else if (payload.kind === "proposedAction") {
    const hasMetadata = granted.has("action:metadata");
    const hasData = granted.has("action:data");
    if (hasMetadata || hasData) {
      const built: Record<string, unknown> = { type: payload.action.type };
      if (hasMetadata) {
        const target = payload.action.target;
        if (target !== undefined) {
          built["target"] = target;
        }
        const destination = payload.action.destination;
        if (destination !== undefined) {
          built["destination"] = destination;
        }
      }
      if (hasData) {
        built["data"] = payload.action.data;
      }
      action = built;
    }
  }

  if (granted.has("secrets:handles")) {
    handles = handlesFromPayload(payload);
  }

  return {
    phase: ctx.phase,
    sessionId: ctx.sessionId,
    riskState: ctx.riskState,
    deadline: ctx.deadline,
    signal: ctx.signal,
    ...(observation !== undefined ? { observation } : {}),
    ...(action !== undefined ? { action } : {}),
    ...(handles !== undefined ? { handles } : {}),
  };
}

function handlesFromPayload(payload: PhasePayload): SecretHandle[] {
  if (payload.kind === "proposedAction") {
    return detectHandles(payload.action.data);
  }
  return [];
}
