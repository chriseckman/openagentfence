import type { ScannerVerdict } from "../contracts/verdict.js";

export interface GuardClassification {
  readonly promptInjection: boolean;
  readonly confidence: number;
  readonly categories: readonly string[];
  readonly recommendedVerdict: ScannerVerdict;
}

/**
 * Validate a structured guard-model response before it is used. Unknown
 * categories are preserved as strings but never mapped to a verdict beyond
 * `warn`; a response failing validation is rejected and surfaces as
 * `scanner_unavailable`, not as a verdict (TB3).
 */
export function validateGuardClassification(input: unknown): GuardClassification | null {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return null;
  }
  const record = input as Record<string, unknown>;
  const promptInjection = record["promptInjection"];
  const confidence = record["confidence"];
  const categories = record["categories"];
  const recommendedVerdict = record["recommendedVerdict"];
  if (typeof promptInjection !== "boolean") {
    return null;
  }
  if (
    typeof confidence !== "number" ||
    !Number.isFinite(confidence) ||
    confidence < 0 ||
    confidence > 1
  ) {
    return null;
  }
  if (!Array.isArray(categories) || categories.some((c) => typeof c !== "string")) {
    return null;
  }
  if (
    recommendedVerdict !== "allow" &&
    recommendedVerdict !== "warn" &&
    recommendedVerdict !== "sanitize" &&
    recommendedVerdict !== "approve" &&
    recommendedVerdict !== "block"
  ) {
    return null;
  }
  return {
    promptInjection,
    confidence,
    categories: [...(categories as string[])],
    recommendedVerdict,
  };
}
