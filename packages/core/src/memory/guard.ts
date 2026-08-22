import type { Finding } from "../contracts/finding.js";
import type { UntrustedContent } from "../contracts/untrusted-content.js";
import type { MemoryWriteCandidate, StoredMemoryItem } from "./item.js";

export const MEMORY_GUARD_REASONS = [
  "memory_item_invalid",
  "memory_content_hash_mismatch",
  "memory_scan_incomplete",
  "memory_bounds_exceeded",
  "memory_write_denied",
  "memory_read_denied",
] as const;
export type MemoryGuardReason = (typeof MEMORY_GUARD_REASONS)[number];

export interface MemoryWriteResult {
  readonly allowed: boolean;
  readonly item?: StoredMemoryItem;
  readonly findings: readonly Finding[];
  readonly reasons: readonly MemoryGuardReason[];
}

export interface SessionMemoryGuard {
  guardWrite(candidate: MemoryWriteCandidate, signal?: AbortSignal): Promise<MemoryWriteResult>;
  guardRead(item: unknown, signal?: AbortSignal): UntrustedContent;
}

/** Value-free typed read failure; candidate/item content is never reflected. */
export class MemoryGuardError extends Error {
  readonly code: MemoryGuardReason;

  constructor(code: MemoryGuardReason) {
    super(code);
    this.name = "MemoryGuardError";
    this.code = code;
  }
}
