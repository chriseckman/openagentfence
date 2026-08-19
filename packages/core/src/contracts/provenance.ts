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

/** The trust ranking, highest first, used to compute least-trust merges. */
export const TRUST_ORDER: readonly TrustLevel[] = ["user", "application", "tool", "memory", "web"];

/** Return the less-trusted of two trust levels (used for merge/downgrade). */
export function leastTrust(a: TrustLevel, b: TrustLevel): TrustLevel {
  const ai = TRUST_ORDER.indexOf(a);
  const bi = TRUST_ORDER.indexOf(b);
  return bi > ai ? b : a;
}

export const WEB_PROVENANCE: DataProvenance = { trust: "web" };
