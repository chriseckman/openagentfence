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
}

export type GuardProviderFailureKind =
  "timeout" | "cancelled" | "exception" | "malformed" | "oversized" | "budget_exhausted";

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
  if (constraints.remainingCalls !== undefined && constraints.remainingCalls <= 0) {
    return { ok: false, kind: "budget_exhausted" };
  }
  if (constraints.remainingTokens !== undefined && constraints.remainingTokens <= 0) {
    return { ok: false, kind: "budget_exhausted" };
  }
  if (Date.now() >= constraints.deadline) {
    return { ok: false, kind: "timeout" };
  }
  if (inputBytes(request) > constraints.maxInputBytes) {
    return { ok: false, kind: "oversized" };
  }

  const remainingMs = Math.max(0, constraints.deadline - Date.now());
  const result = await runWithDeadline<unknown>(
    (signal) => provider.classify(request, { ...constraints, signal }),
    remainingMs,
    constraints.signal,
  );
  if (!result.ok) {
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

function inputBytes(request: GuardClassificationRequest): number {
  let bytes = request.taskSummary.length;
  for (const excerpt of request.excerpts) {
    bytes += excerpt.length;
  }
  for (const hint of request.localeHints) {
    bytes += hint.length;
  }
  return bytes;
}

function outputBytes(value: GuardClassification): number {
  return JSON.stringify(value).length;
}
