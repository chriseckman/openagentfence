import {
  mintHandle,
  serializeHandle,
  type ExecutorSecretLookup,
  type SecretHandle,
  type SecretHandleKind,
  type SessionVault,
  type VaultAdapter,
} from "@openagentfence/core";

/** The package name of this library. @public */
export const PACKAGE_NAME = "@openagentfence/vault";

/** Bounded configuration for the non-persistent reference vault. @public */
export interface InMemoryVaultOptions {
  readonly maxEntriesPerSession?: number;
  readonly maxValueBytes?: number;
  readonly ttlMs?: number;
  readonly now?: () => number;
}

const DEFAULT_MAX_ENTRIES = 64;
const DEFAULT_MAX_VALUE_BYTES = 16 * 1024;
const DEFAULT_TTL_MS = 30 * 60 * 1000;

interface Entry {
  readonly handle: SecretHandle;
  readonly value: string;
  readonly expiresAt: number;
}

/**
 * Create the v0.1 reference vault. Values stay in process memory and are
 * reachable only through a session-scoped executor lookup capability.
 */
export function inMemoryVault(options: InMemoryVaultOptions = {}): VaultAdapter {
  const maxEntries = options.maxEntriesPerSession ?? DEFAULT_MAX_ENTRIES;
  const maxValueBytes = options.maxValueBytes ?? DEFAULT_MAX_VALUE_BYTES;
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const now = options.now ?? Date.now;
  if (!Number.isInteger(maxEntries) || maxEntries < 1)
    throw new TypeError("maxEntriesPerSession must be positive");
  if (!Number.isInteger(maxValueBytes) || maxValueBytes < 1)
    throw new TypeError("maxValueBytes must be positive");
  if (!Number.isFinite(ttlMs) || ttlMs < 1) throw new TypeError("ttlMs must be positive");

  const sessions = new Map<string, InMemorySessionVault>();
  return {
    openSession(sessionId: string): SessionVault {
      if (!/^[a-f0-9]{16}$/.test(sessionId)) throw new TypeError("invalid session id");
      const existing = sessions.get(sessionId);
      if (existing !== undefined) return existing;
      const session = new InMemorySessionVault(
        sessionId,
        maxEntries,
        maxValueBytes,
        ttlMs,
        now,
        () => {
          sessions.delete(sessionId);
        },
      );
      sessions.set(sessionId, session);
      return session;
    },
  };
}

class InMemorySessionVault implements SessionVault {
  private readonly entries = new Map<string, Entry>();
  private invalidated = false;

  constructor(
    private readonly sessionId: string,
    private readonly maxEntries: number,
    private readonly maxValueBytes: number,
    private readonly ttlMs: number,
    private readonly now: () => number,
    private readonly onInvalidate: () => void,
  ) {}

  async store(
    name: string,
    value: string,
    kind: SecretHandleKind = "SECRET",
  ): Promise<SecretHandle> {
    this.requireActive();
    if (Buffer.byteLength(value, "utf8") > this.maxValueBytes)
      throw new RangeError("secret value exceeds vault limit");
    if (this.entries.size >= this.maxEntries)
      throw new RangeError("vault session handle limit reached");
    let handle: SecretHandle;
    do {
      handle = mintHandle(kind, name);
    } while (this.entries.has(serializeHandle(handle)));
    this.entries.set(serializeHandle(handle), {
      handle,
      value,
      expiresAt: this.now() + this.ttlMs,
    });
    return handle;
  }

  createExecutorLookup(): ExecutorSecretLookup {
    return {
      lookup: async (handle: SecretHandle, signal?: AbortSignal): Promise<string | null> => {
        if (signal?.aborted === true || this.invalidated) return null;
        const key = serializeHandle(handle);
        const entry = this.entries.get(key);
        if (entry === undefined || entry.expiresAt <= this.now()) {
          this.entries.delete(key);
          return null;
        }
        return entry.value;
      },
    };
  }

  async invalidateSession(): Promise<void> {
    if (this.invalidated) return;
    this.invalidated = true;
    this.entries.clear();
    this.onInvalidate();
  }

  private requireActive(): void {
    if (this.invalidated) throw new Error(`vault session ${this.sessionId} is no longer active`);
  }
}
