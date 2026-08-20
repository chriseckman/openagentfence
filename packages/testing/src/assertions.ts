import { secretRedactionForms, type AggregateVerdict, type Finding } from "@openagentfence/core";

/**
 * Focused assertion helpers (OAF-TEST-001). These express verdict/finding/
 * secret-absence checks without reimplementing security policy in the testing
 * package.
 */

/** Assert a serializable object/string contains no raw synthetic secret value. */
export function expectNoRawSecret(value: unknown, secret: string): boolean {
  return !JSON.stringify(value).includes(secret);
}

/**
 * Registry-aware artifact assertion for exact and documented normalized secret
 * forms. Handles cycles and Error messages without throwing while testing a
 * leak boundary.
 */
export function expectNoRawSecretIn(value: unknown, secret: string): boolean {
  const seen = new WeakSet();
  const serialized = JSON.stringify(value, (_key, item: unknown) => {
    if (item instanceof Error) return { name: item.name, message: item.message };
    if (typeof item === "object" && item !== null) {
      if (seen.has(item)) return "[CYCLE]";
      seen.add(item);
    }
    return item;
  });
  const text = serialized;
  return ![secret, ...secretRedactionForms(secret)].some(
    (form) => form.length > 0 && text.includes(form),
  );
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
