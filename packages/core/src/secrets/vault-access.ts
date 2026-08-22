/**
 * An unforgeable core capability required to open a vault session and obtain
 * its executor lookup. Vault implementations may inspect it, but only core
 * mints it. This prevents an application that merely holds a `VaultAdapter`
 * from turning a registered handle back into a raw value (ADR-0005).
 * @experimental
 */
export interface VaultExecutorAccess {
  readonly __openagentfenceVaultExecutorAccess: unique symbol;
}

const accessCapabilities = new WeakSet();

/** @internal Core creates this once for each firewall-owned vault session. */
export function createVaultExecutorAccess(): VaultExecutorAccess {
  const access = Object.freeze({}) as VaultExecutorAccess;
  accessCapabilities.add(access);
  return access;
}

/** Runtime guard required by vault implementations before returning raw lookup access. */
export function isVaultExecutorAccess(value: unknown): value is VaultExecutorAccess {
  return typeof value === "object" && value !== null && accessCapabilities.has(value);
}
