export const TRUST_LEVELS = ["user", "application", "web", "tool", "memory"] as const;

export type TrustLevel = (typeof TRUST_LEVELS)[number];

/**
 * Provenance of security-relevant data (PRD §13.4, ARCHITECTURE §4).
 * Attached to observations, findings, action data, and memory. Trust ordering:
 * `user > application > tool ≈ memory > web`.
 */
export interface DataProvenance {
  readonly trust: TrustLevel;
  readonly origin?: string;
  readonly frameOrigin?: string;
  readonly pageId?: string;
  readonly elementId?: string;
  readonly timestamp?: string;
}

/**
 * A bounded value that crosses a security boundary together with its source
 * metadata. The carrier is deliberately shallow: v0.1 does not claim
 * recursive or character-level taint tracking (ADR-0017).
 */
export interface ProvenancedDatum<T = unknown> {
  readonly value: T;
  readonly provenance: DataProvenance;
}

const MAX_PROVENANCE_TEXT = 2_048;

/** Validate the bounded, closed provenance shape at security boundaries. */
export function validateDataProvenance(value: unknown): DataProvenance | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const allowed = new Set(["trust", "origin", "frameOrigin", "pageId", "elementId", "timestamp"]);
  if (Object.keys(record).some((key) => !allowed.has(key))) return null;
  if (!TRUST_LEVELS.includes(record["trust"] as TrustLevel)) return null;
  const out: Record<string, string> = { trust: record["trust"] as string };
  for (const key of ["origin", "frameOrigin", "pageId", "elementId", "timestamp"] as const) {
    const field = record[key];
    if (field !== undefined) {
      if (typeof field !== "string" || field.length === 0 || field.length > MAX_PROVENANCE_TEXT)
        return null;
      if (key === "timestamp" && Number.isNaN(Date.parse(field))) return null;
      out[key] = field;
    }
  }
  return Object.freeze(out) as unknown as DataProvenance;
}

/** Create a provenance carrier after validating its source metadata. */
export function provenanced<T>(value: T, provenance: unknown): ProvenancedDatum<T> {
  const validated = validateDataProvenance(provenance);
  if (validated === null) throw new TypeError("datum requires valid bounded provenance");
  return Object.freeze({ value, provenance: validated });
}

/** The trust ranking, highest first, used to compute least-trust merges. */
export const TRUST_ORDER: readonly TrustLevel[] = ["user", "application", "tool", "memory", "web"];

/** Return the less-trusted of two trust levels (used for merge/downgrade). */
export function leastTrust(a: TrustLevel, b: TrustLevel): TrustLevel {
  const ai = TRUST_ORDER.indexOf(a);
  const bi = TRUST_ORDER.indexOf(b);
  return bi > ai ? b : a;
}

export const WEB_PROVENANCE: DataProvenance = { trust: "web" };
