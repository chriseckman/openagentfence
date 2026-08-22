import { secretRedactionForms, type AggregateVerdict, type Finding } from "@openagentfence/core";

/**
 * Focused assertion helpers (OAF-TEST-001). These express verdict/finding/
 * secret-absence checks without reimplementing security policy in the testing
 * package.
 */

/** Assert a serializable object/string contains no raw synthetic secret value. */
export function expectNoRawSecret(value: unknown, secrets: string | readonly string[]): boolean {
  const serialized = serializeArtifact(value);
  return secretList(secrets).every((secret) => !serialized.includes(secret));
}

/**
 * Registry-aware artifact assertion for exact and documented normalized secret
 * forms. Handles cycles and Error messages without throwing while testing a
 * leak boundary.
 */
export function expectNoRawSecretIn(value: unknown, secrets: string | readonly string[]): boolean {
  const text = serializeArtifact(value);
  return secretList(secrets).every((secret) =>
    [secret, ...secretRedactionForms(secret)].every(
      (form) => form.length === 0 || !text.includes(form),
    ),
  );
}

function serializeArtifact(value: unknown): string {
  if (value === undefined || typeof value === "symbol" || typeof value === "function") {
    return String(value);
  }
  const seen = new WeakSet();
  const serialized = JSON.stringify(value, (_key, item: unknown) => {
    if (item instanceof Error) return { name: item.name, message: item.message };
    if (typeof item === "bigint") return item.toString();
    if (typeof item === "object" && item !== null) {
      if (seen.has(item)) return "[CYCLE]";
      seen.add(item);
    }
    return item;
  });
  return serialized;
}

function secretList(secrets: string | readonly string[]): readonly string[] {
  return typeof secrets === "string" ? [secrets] : secrets;
}

/** True when any finding has the given category. */
export function hasFindingCategory(findings: readonly Finding[], category: string): boolean {
  return findings.some((f) => f.category === category);
}

/** Canonical named helper for corpus assertions. */
export function expectFinding(findings: readonly Finding[], category: string): boolean {
  return hasFindingCategory(findings, category);
}

/** True when the verdict is one of the blocking/restricting outcomes. */
export function isBlockingVerdict(verdict: AggregateVerdict): boolean {
  return verdict === "BLOCK" || verdict === "RESTRICT" || verdict === "QUARANTINE";
}

/** True when a decision-shaped result is a deterministic blocking outcome. */
export function expectBlocked(
  value: AggregateVerdict | { readonly verdict: AggregateVerdict },
): boolean {
  return isBlockingVerdict(typeof value === "string" ? value : value.verdict);
}

/** True when a result exposes exactly the expected aggregate verdict. */
export function expectVerdict(
  value: AggregateVerdict | { readonly verdict: AggregateVerdict },
  expected: AggregateVerdict,
): boolean {
  return (typeof value === "string" ? value : value.verdict) === expected;
}

/** Extract reason codes from a decision-shaped object. */
export function reasonsOf(decision: { readonly reasons?: readonly string[] }): readonly string[] {
  return decision.reasons ?? [];
}
