/**
 * Unforgeable session capability for raw framework access. The public escape
 * hatch records use before supplying it to an adapter (INV-18).
 * @experimental
 */
export interface UnsafeAdapterAccess {
  readonly __openagentfenceUnsafeAdapterAccess: unique symbol;
}

const rawAccessCapabilities = new WeakSet();

/** @internal Only `SecuritySession` creates adapter raw-access capabilities. */
export function createUnsafeAdapterAccess(): UnsafeAdapterAccess {
  const access = Object.freeze({}) as UnsafeAdapterAccess;
  rawAccessCapabilities.add(access);
  return access;
}

/** Runtime guard adapters use before exposing a raw framework handle. */
export function isUnsafeAdapterAccess(value: unknown): value is UnsafeAdapterAccess {
  return typeof value === "object" && value !== null && rawAccessCapabilities.has(value);
}
