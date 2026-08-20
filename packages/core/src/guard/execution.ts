import type { GuardClassification } from "./classification.js";
import { validateGuardClassification } from "./classification.js";
import type { GuardClassificationRequest } from "./request.js";
import type { GuardModelProvider } from "./provider.js";
import { runWithDeadline } from "../orchestrator/timeouts.js";

/**
 * Per-call execution constraints for a guard-model provider (OAF-CORE-018).
 * Every provider call receives an `AbortSignal`, an absolute deadline, input
 * and output byte bounds, token caps, and remaining session budgets. Provider
 * output is `unknown` until `runGuardProvider` validates it.
 */
export interface GuardExecutionConstraints {
  readonly signal: AbortSignal;
  readonly deadline: number;
  readonly maxInputBytes: number;
  readonly maxOutputBytes: number;
  readonly maxTokens?: number;
  readonly remainingCalls?: number;
  readonly remainingTokens?: number;
  /**
   * Session-owned atomic reservation invoked immediately before each provider
   * dispatch. Composite providers invoke it again before a fallback attempt.
   */
  readonly reserveDispatch?: (reservation: GuardDispatchReservation) => boolean;
}

export interface GuardDispatchReservation {
  readonly calls: number;
  readonly tokens: number;
}

export type GuardProviderFailureKind =
  | "timeout"
  | "cancelled"
  | "exception"
  | "malformed"
  | "oversized"
  | "budget_exhausted"
  | "unavailable";

/** Stable value-free failure thrown by provider implementations. */
export class GuardProviderRuntimeError extends Error {
  readonly kind: GuardProviderFailureKind;

  constructor(kind: GuardProviderFailureKind) {
    super(`guard provider ${kind}`);
    this.name = "GuardProviderRuntimeError";
    this.kind = kind;
  }
}

export type GuardProviderOutcome =
  | { readonly ok: true; readonly value: GuardClassification }
  | { readonly ok: false; readonly kind: GuardProviderFailureKind };

export const DEFAULT_GUARD_EXECUTION_LIMITS = {
  maxInputBytes: 32_000,
  maxOutputBytes: 16_000,
  maxTokens: 4096,
  maxCalls: 100,
  maxTokensTotal: 100_000,
} as const;

/**
 * Run a guard-model provider under the full execution contract. Provider output
 * is treated as `unknown` and only a schema-valid, in-bounds classification
 * becomes an outcome; every other path is a typed, fail-closed failure
 * (INV-03, INV-09, INV-16). A provider that ignores its signal still settles
 * via the deadline/parent-cancellation race.
 */
export async function runGuardProvider(
  provider: GuardModelProvider,
  request: GuardClassificationRequest,
  constraints: GuardExecutionConstraints,
): Promise<GuardProviderOutcome> {
  if (constraints.signal.aborted) {
    return { ok: false, kind: "cancelled" };
  }
  if (constraints.remainingCalls !== undefined && constraints.remainingCalls <= 0) {
    return { ok: false, kind: "budget_exhausted" };
  }
  const tokens = guardTokenReservation(request, constraints);
  if (
    constraints.remainingTokens !== undefined &&
    (constraints.remainingTokens <= 0 || constraints.remainingTokens < tokens)
  ) {
    return { ok: false, kind: "budget_exhausted" };
  }
  if (Date.now() >= constraints.deadline) {
    return { ok: false, kind: "timeout" };
  }
  if (inputBytes(request) > constraints.maxInputBytes) {
    return { ok: false, kind: "oversized" };
  }
  if (request.budget?.maxTokens !== undefined && request.budget.maxTokens > tokens) {
    return { ok: false, kind: "budget_exhausted" };
  }
  if (constraints.reserveDispatch?.({ calls: 1, tokens }) === false) {
    return { ok: false, kind: "budget_exhausted" };
  }

  const remainingMs = Math.max(0, constraints.deadline - Date.now());
  const result = await runWithDeadline<unknown>(
    (signal) => provider.classify(request, { ...constraints, signal }),
    remainingMs,
    constraints.signal,
  );
  if (!result.ok) {
    if (result.error instanceof GuardProviderRuntimeError) {
      return { ok: false, kind: result.error.kind };
    }
    return { ok: false, kind: result.kind };
  }
  const validated = validateGuardClassification(result.value);
  if (validated === null) {
    return { ok: false, kind: "malformed" };
  }
  if (outputBytes(validated) > constraints.maxOutputBytes) {
    return { ok: false, kind: "oversized" };
  }
  return { ok: true, value: validated };
}

/** Conservative token authority reserved before a provider dispatch. */
export function guardTokenReservation(
  request: GuardClassificationRequest,
  constraints: GuardExecutionConstraints,
): number {
  return Math.max(
    0,
    Math.floor(
      request.budget?.maxTokens ??
        constraints.maxTokens ??
        DEFAULT_GUARD_EXECUTION_LIMITS.maxTokens,
    ),
  );
}

function inputBytes(request: GuardClassificationRequest): number {
  let bytes = Buffer.byteLength(request.taskSummary, "utf8");
  for (const excerpt of request.excerpts) {
    bytes += Buffer.byteLength(excerpt, "utf8");
  }
  for (const hint of request.localeHints) {
    bytes += Buffer.byteLength(hint, "utf8");
  }
  return bytes;
}

function outputBytes(value: GuardClassification): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}
