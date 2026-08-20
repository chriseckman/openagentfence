import {
  detectHandles,
  inferSecretFieldType,
  parseHandle,
  type IntentStateSnapshot,
  type SecretResolver,
} from "@openagentfence/core";
import type { PlaywrightOperation } from "./wrap.js";

export interface ExecutorArgument {
  readonly value: string;
  readonly sensitive: boolean;
}

const SUPPORTED_SECRET_METHODS = new Set<PlaywrightOperation["method"]>([
  "fill",
  "type",
  "selectOption",
]);

/** Resolve one whole-value handle after live state revalidation. */
export async function executorArgument(
  operation: PlaywrightOperation,
  state: IntentStateSnapshot,
  resolver: SecretResolver,
): Promise<ExecutorArgument> {
  const value = requiredArgument(operation);
  const handles = detectHandles(operation.arguments);
  if (handles.length === 0) return { value, sensitive: false };
  if (!SUPPORTED_SECRET_METHODS.has(operation.method) || operation.arguments.length !== 1) {
    throw new TypeError("secret handles are not supported for this Playwright operation");
  }
  const handle = parseHandle(value);
  if (handle === null || handles.length !== 1) {
    throw new TypeError("Playwright secret sinks require exactly one whole-value handle");
  }
  const fieldType = inferSecretFieldType(state.securityAttributes);
  const selector = state.target.selector ?? state.target.element;
  if (fieldType === null || selector === undefined || state.target.origin === undefined) {
    throw new TypeError("Playwright secret sink field metadata is unavailable");
  }
  const resolved = await resolver.resolveForSink(handle, {
    origin: state.target.origin,
    fieldType,
    selector,
    ...(state.formAction !== undefined ? { formAction: state.formAction } : {}),
  });
  if (resolved === null) throw new TypeError("Playwright secret sink resolution was denied");
  return { value: resolved, sensitive: true };
}

export function assertSecretOperationSupported(operation: PlaywrightOperation): void {
  if (
    detectHandles(operation.arguments).length > 0 &&
    !SUPPORTED_SECRET_METHODS.has(operation.method)
  ) {
    throw new TypeError("secret handles are not supported for this Playwright operation");
  }
}

/** Keep the materialized value inside the final framework-call callback. */
export async function withExecutorArgument(
  operation: PlaywrightOperation,
  state: IntentStateSnapshot,
  resolver: SecretResolver,
  execute: (value: string) => Promise<unknown>,
): Promise<void> {
  const argument = await executorArgument(operation, state, resolver);
  try {
    await execute(argument.value);
  } catch (error) {
    if (argument.sensitive) {
      throw new TypeError("Playwright secret sink execution failed");
    }
    throw error;
  }
}

function requiredArgument(operation: PlaywrightOperation): string {
  const value = operation.arguments[0];
  if (value === undefined) throw new TypeError("playwright operation lacks an argument");
  return value;
}
