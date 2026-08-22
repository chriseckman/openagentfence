import type { SecretHandle } from "./handle-codec.js";
import type { VaultExecutorAccess } from "./vault-access.js";

/** Executor-only capability for resolving a handle after core has authorized its sink. */
export interface ExecutorSecretLookup {
  lookup(handle: SecretHandle, signal?: AbortSignal): Promise<string | null>;
}

/** A vault view bound to exactly one firewall session. */
export interface SessionVault {
  store(name: string, value: string, kind?: SecretHandle["kind"]): Promise<SecretHandle>;
  /** Returns raw values only for a session-private capability minted by core. */
  createExecutorLookup(access: VaultExecutorAccess): ExecutorSecretLookup;
  invalidateSession(): Promise<void>;
}

/**
 * Storage for secret values, keyed by handle (ADR-0005). Implementations must
 * not perform authorization — that lives in `core`'s `SecretResolver` — and
 * must not log values. `lookup` is reachable only from the adapter executor
 * path through a scoped resolver.
 */
export interface VaultAdapter {
  /** Opens a session only when core supplies its unforgeable executor capability. */
  openSession(sessionId: string, access: VaultExecutorAccess): SessionVault;
}
