import { hash } from "../trace/redact.js";

/**
 * Deterministic, locale-independent, property-order-independent serialization
 * used for state fingerprints (ADR-0010, INV-19). Object keys are sorted before
 * serialization so two structurally equal snapshots always hash identically.
 */
export function stableSerialize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      sorted[key] = sortValue(record[key]);
    }
    return sorted;
  }
  return value;
}

/** SHA-256 hex fingerprint of a deterministically serialized value. */
export function fingerprint(value: unknown): string {
  return hash(stableSerialize(value));
}
