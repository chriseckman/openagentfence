import type { ElementHandle } from "playwright";

/**
 * Adapter-private binding between an authorized structured operation and the
 * exact Playwright element observed by the secure wrapper. It is deliberately
 * absent from the operation object, serialization, traces, and public API.
 */
const exactTargets = new WeakMap<object, ElementHandle>();

export function bindExactTarget(operation: object, handle: ElementHandle): void {
  exactTargets.set(operation, handle);
}

export function exactTargetHandle(operation: unknown): ElementHandle | undefined {
  return typeof operation === "object" && operation !== null
    ? exactTargets.get(operation)
    : undefined;
}
