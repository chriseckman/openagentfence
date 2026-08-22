import type { Authorized } from "../action/authorized.js";
import { isIntentExpired } from "../action/intent.js";
import { fingerprint } from "../action/state-fingerprint.js";
import type { RiskState } from "../contracts/risk-state.js";
import type { CapabilityEnvelope } from "../envelope/envelope.js";
import { originOf } from "../action/url.js";
import { REASON_CODES, type ReasonCode } from "../policy/reasons.js";
import { detectHandles, serializeHandle, type SecretHandle } from "./handle-codec.js";
import type { SinkBinding, SinkTarget } from "./sink-binding.js";
import type { ExecutorSecretLookup } from "./vault-adapter.js";

/** Firewall-owned live state consulted immediately before vault access. */
export interface ResolverSessionState {
  readonly riskState: RiskState;
  readonly policyHash: string;
  readonly sessionActive: boolean;
  readonly actionStateValid: boolean;
}

/** Redacted audit record for a resolution attempt. */
export interface SecretResolutionAudit {
  readonly handleFingerprint: string;
  readonly sinkFingerprint: string;
  readonly outcome: "allowed" | "denied" | "unavailable";
  readonly reason?: ReasonCode;
}

/** The executor-only view: raw values never leave this callback boundary. */
export interface SecretResolver {
  resolveForSink(handle: SecretHandle, target: SinkTarget): Promise<string | null>;
}

/** Core-owned lifecycle controls are deliberately not exposed to adapters. */
export interface ScopedSecretResolver extends SecretResolver {
  commit(): void;
  revoke(): void;
}

export interface ScopedSecretResolverOptions {
  readonly authorized: Authorized;
  readonly bindings: readonly SinkBinding[];
  readonly envelope: CapabilityEnvelope;
  readonly lookup: ExecutorSecretLookup;
  readonly currentState: () => ResolverSessionState;
  readonly restrictedMode?: "keep_approved_sinks" | "deny_all";
  readonly wasApproved: (sinkKey: string) => boolean;
  readonly approve: (sinkKey: string) => void;
  readonly audit?: (attempt: SecretResolutionAudit) => void;
}

/**
 * Mint an action-scoped resolver. It validates every deterministic condition
 * before touching the vault and commits NORMAL-state sink approvals only
 * after the exact adapter execution succeeds (ADR-0005, INV-04/19).
 */
export function createScopedSecretResolver(
  options: ScopedSecretResolverOptions,
): ScopedSecretResolver {
  let active = true;
  const controller = new AbortController();
  const pendingApprovals = new Set<string>();
  const resolvedHandles = new Set<string>();
  const actionHandles = new Set(detectHandles(options.authorized.action).map(serializeHandle));

  const deny = (handle: SecretHandle, target: SinkTarget, reason: ReasonCode): null => {
    options.audit?.({
      handleFingerprint: fingerprint(serializeHandle(handle)),
      sinkFingerprint: fingerprint(target),
      outcome: "denied",
      reason,
    });
    return null;
  };

  return {
    async resolveForSink(handle: SecretHandle, target: SinkTarget): Promise<string | null> {
      if (!active) return deny(handle, target, REASON_CODES.action_intent_mismatch);
      const state = options.currentState();
      if (
        !state.sessionActive ||
        state.riskState === "READ_ONLY" ||
        state.riskState === "QUARANTINED"
      ) {
        return deny(handle, target, REASON_CODES.session_restricted);
      }
      if (
        !state.actionStateValid ||
        state.policyHash !== options.authorized.policyHash ||
        isIntentExpired(options.authorized.intent)
      ) {
        return deny(handle, target, REASON_CODES.action_intent_mismatch);
      }
      if (
        !options.envelope.credentials ||
        !options.envelope.evaluate(options.authorized.action).allowed
      ) {
        return deny(handle, target, REASON_CODES.capability_denied);
      }

      const handleKey = serializeHandle(handle);
      if (!actionHandles.has(handleKey) || resolvedHandles.has(handleKey)) {
        return deny(handle, target, REASON_CODES.secret_sink_not_allowed);
      }
      const binding = options.bindings.find(
        (candidate) => candidate.name === handle.name && candidate.kind === handle.kind,
      );
      if (binding === undefined || !targetMatches(options.authorized, binding, target)) {
        return deny(handle, target, REASON_CODES.secret_sink_not_allowed);
      }

      const sinkKey = `${handleKey}|${fingerprint(target)}`;
      if (
        state.riskState === "RESTRICTED" &&
        (options.restrictedMode === "deny_all" || !options.wasApproved(sinkKey))
      ) {
        return deny(handle, target, REASON_CODES.session_restricted);
      }

      const value = await options.lookup.lookup(handle, controller.signal);
      if (value === null) {
        options.audit?.({
          handleFingerprint: fingerprint(handleKey),
          sinkFingerprint: fingerprint(target),
          outcome: "unavailable",
          reason: REASON_CODES.secret_sink_not_allowed,
        });
        return null;
      }
      resolvedHandles.add(handleKey);
      if (state.riskState === "NORMAL") pendingApprovals.add(sinkKey);
      options.audit?.({
        handleFingerprint: fingerprint(handleKey),
        sinkFingerprint: fingerprint(target),
        outcome: "allowed",
      });
      return value;
    },
    commit(): void {
      if (!active) return;
      for (const sinkKey of pendingApprovals) options.approve(sinkKey);
      pendingApprovals.clear();
    },
    revoke(): void {
      if (!active) return;
      active = false;
      pendingApprovals.clear();
      controller.abort();
    },
  };
}

/** Fail-closed resolver used when no session vault is available. */
export const denyAllResolver: SecretResolver = {
  async resolveForSink(): Promise<string | null> {
    return null;
  },
};

function targetMatches(authorized: Authorized, binding: SinkBinding, target: SinkTarget): boolean {
  const origin = canonicalOrigin(target.origin);
  if (
    origin === null ||
    target.origin !== origin ||
    target.fieldType.length === 0 ||
    target.fieldType.length > 64
  ) {
    return false;
  }
  if (!binding.origins.includes(origin) || !binding.fieldTypes.includes(target.fieldType)) {
    return false;
  }

  const intent = authorized.intent;
  const liveOrigins = [intent.target.origin, intent.destination, intent.formAction]
    .filter((value): value is string => value !== undefined)
    .map(canonicalOrigin);
  if (
    liveOrigins.length === 0 ||
    liveOrigins.some((value) => value === null || !binding.origins.includes(value)) ||
    !liveOrigins.includes(origin)
  ) {
    return false;
  }

  const intentSelector = intent.target.selector ?? intent.target.element;
  if (intentSelector !== undefined && target.selector !== intentSelector) return false;
  if (binding.selector !== undefined && target.selector !== binding.selector) return false;
  if (intent.formAction !== undefined && target.formAction !== intent.formAction) return false;
  if (intent.formAction === undefined && target.formAction !== undefined) return false;
  if (binding.formAction !== undefined && target.formAction !== binding.formAction) return false;
  return true;
}

function canonicalOrigin(value: string): string | null {
  return originOf(value);
}
