import type { CanonicalAction } from "./canonical-action.js";

/**
 * Adapters implement this to map framework-specific operations into
 * `CanonicalAction`. Unknown operations must normalize conservatively (to
 * `UNKNOWN`), never to a permissive type (ADR-0002, PRD §13.7).
 */
export interface ActionNormalizer {
  normalize(operation: unknown): CanonicalAction;
}

/** A normalizer that conservatively maps anything to `UNKNOWN`. */
export function unknownActionNormalizer(operation: unknown): CanonicalAction {
  return {
    type: "UNKNOWN",
    instructionProvenance: { trust: "application" },
    raw: operation,
  };
}
