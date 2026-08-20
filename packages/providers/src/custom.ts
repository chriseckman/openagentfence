import {
  GuardProviderRuntimeError,
  guardTokenReservation,
  runWithDeadline,
  validateGuardClassification,
  type GuardExecutionConstraints,
  type GuardModelProvider,
} from "@openagentfence/core";
import type { CustomGuardProviderOptions } from "./config.js";
import { GuardProviderConstructionError, validateProviderOptions } from "./config.js";

/** Create the reference callback provider under the shared bounded contract. */
export function customGuardProvider(options: CustomGuardProviderOptions): GuardModelProvider {
  const validated = validateProviderOptions(options, ["callback", "makesExternalCalls"]);
  if (typeof options.callback !== "function" || typeof options.makesExternalCalls !== "boolean") {
    throw new GuardProviderConstructionError("invalid_options");
  }
  const callback = options.callback;
  const fallback = validated.fallback;
  const provider: GuardModelProvider = {
    name: "custom",
    model: validated.model,
    makesExternalCalls: options.makesExternalCalls,
    async classify(request, constraints) {
      if (!validated.roles.has(request.role)) {
        throw new GuardProviderRuntimeError("unavailable");
      }
      const result = await invoke(callback, request, constraints, validated.timeoutMs);
      let failureKind: "timeout" | "cancelled" | "exception" | "malformed" | "oversized";
      if (result.ok) {
        if (isBoundedClassification(result.value, constraints.maxOutputBytes)) {
          return result.value;
        }
        failureKind = "malformed";
      } else {
        failureKind = result.kind;
      }
      if (failureKind === "cancelled" || fallback === undefined) {
        throw new GuardProviderRuntimeError(failureKind);
      }
      reserveFallback(request, constraints);
      return fallback.classify(request, constraints);
    },
  };
  return Object.freeze(provider);
}

async function invoke(
  callback: GuardModelProvider["classify"],
  request: Parameters<GuardModelProvider["classify"]>[0],
  constraints: GuardExecutionConstraints,
  timeoutMs: number,
): Promise<
  | { readonly ok: true; readonly value: unknown }
  | {
      readonly ok: false;
      readonly kind: "timeout" | "cancelled" | "exception" | "malformed" | "oversized";
    }
> {
  const deadline = Math.min(constraints.deadline, Date.now() + timeoutMs);
  const result = await runWithDeadline(
    (signal) => callback(request, { ...constraints, signal, deadline }),
    Math.max(0, deadline - Date.now()),
    constraints.signal,
  );
  if (!result.ok) return { ok: false, kind: result.kind };
  if (validateGuardClassification(result.value) === null) {
    return { ok: false, kind: "malformed" };
  }
  if (!isBoundedClassification(result.value, constraints.maxOutputBytes)) {
    return { ok: false, kind: "oversized" };
  }
  return { ok: true, value: result.value };
}

function reserveFallback(
  request: Parameters<GuardModelProvider["classify"]>[0],
  constraints: GuardExecutionConstraints,
): void {
  const tokens = guardTokenReservation(request, constraints);
  if (
    (constraints.remainingCalls !== undefined && constraints.remainingCalls < 2) ||
    (constraints.remainingTokens !== undefined && constraints.remainingTokens < tokens * 2) ||
    constraints.reserveDispatch?.({ calls: 1, tokens }) === false
  ) {
    throw new GuardProviderRuntimeError("budget_exhausted");
  }
}

function isBoundedClassification(value: unknown, maxOutputBytes: number): boolean {
  if (validateGuardClassification(value) === null) return false;
  try {
    return Buffer.byteLength(JSON.stringify(value), "utf8") <= maxOutputBytes;
  } catch {
    return false;
  }
}
