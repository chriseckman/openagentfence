import type { AggregateVerdict, Finding } from "@openagentfence/core";

/**
 * Focused assertion helpers (OAF-TEST-001). These express verdict/finding/
 * secret-absence checks without reimplementing security policy in the testing
 * package.
 */

/** Assert a serializable object/string contains no raw synthetic secret value. */
export function expectNoRawSecret(value: unknown, secret: string): boolean {
  return !JSON.stringify(value).includes(secret);
}

/** True when any finding has the given category. */
export function hasFindingCategory(findings: readonly Finding[], category: string): boolean {
  return findings.some((f) => f.category === category);
}

/** True when the verdict is one of the blocking/restricting outcomes. */
export function isBlockingVerdict(verdict: AggregateVerdict): boolean {
  return verdict === "BLOCK" || verdict === "RESTRICT" || verdict === "QUARANTINE";
}

/** Extract reason codes from a decision-shaped object. */
export function reasonsOf(decision: { readonly reasons?: readonly string[] }): readonly string[] {
  return decision.reasons ?? [];
}
