import type { SecretHandle } from "./handle-codec.js";

/**
 * Storage for secret values, keyed by handle (ADR-0005). Implementations must
 * not perform authorization — that lives in `core`'s `SecretResolver` — and
 * must not log values. `lookup` is reachable only from the adapter executor
 * path through a scoped resolver.
 */
export interface VaultAdapter {
  store(name: string, value: string): Promise<SecretHandle>;
  lookup(handle: SecretHandle): Promise<string | null>;
  invalidateSession(): Promise<void>;
}
