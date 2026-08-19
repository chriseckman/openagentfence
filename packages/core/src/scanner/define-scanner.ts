import type { SecurityScanner } from "./scanner.js";
import { SECURITY_PHASES } from "../contracts/phase.js";
import { kindForTier, defaultTierForKind } from "../guard/tier.js";

/**
 * Register a scanner (PRD §11). Registration is explicit — an import of
 * `defineScanner` — never name-based loading (INV-16, no arbitrary code
 * execution). Resolves and validates the detector tier (OAF-CORE-018) and
 * returns a frozen scanner definition.
 */
export function defineScanner(scanner: SecurityScanner): Readonly<SecurityScanner> {
  if (scanner.id.trim().length === 0) {
    throw new TypeError("scanner id must be a non-empty string");
  }
  if (scanner.phases.length === 0) {
    throw new TypeError(`scanner ${scanner.id} must declare at least one phase`);
  }
  for (const phase of scanner.phases) {
    if (!(SECURITY_PHASES as readonly string[]).includes(phase)) {
      throw new TypeError(`scanner ${scanner.id} has invalid phase: ${phase}`);
    }
  }
  const kind: string = scanner.kind;
  if (kind !== "deterministic" && kind !== "semantic") {
    throw new TypeError(`scanner ${scanner.id} has invalid kind: ${kind}`);
  }
  const tier = scanner.tier ?? defaultTierForKind(kind);
  if (kindForTier(tier) !== kind) {
    throw new TypeError(
      `scanner ${scanner.id} declares tier ${tier}, which requires kind ${kindForTier(tier)}`,
    );
  }
  return Object.freeze({ ...scanner, tier });
}
