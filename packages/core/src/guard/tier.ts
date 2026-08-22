/**
 * Detector tiers (OAF-CORE-018). Tier 0 is deterministic; Tier 1 (specialized
 * classifier) and Tier 2 (semantic guard) are `kind: "semantic"` and produce
 * evidence only — never authority (INV-03, INV-20).
 */
export const DETECTOR_TIERS = ["tier0", "tier1", "tier2"] as const;

export type DetectorTier = (typeof DETECTOR_TIERS)[number];

export const TIER_KINDS: Readonly<Record<DetectorTier, "deterministic" | "semantic">> = {
  tier0: "deterministic",
  tier1: "semantic",
  tier2: "semantic",
};

/** The `kind` a given tier must declare. */
export function kindForTier(tier: DetectorTier): "deterministic" | "semantic" {
  return TIER_KINDS[tier];
}

/** Resolve the tier for a scanner kind when no explicit tier is declared. */
export function defaultTierForKind(kind: "deterministic" | "semantic"): DetectorTier {
  return kind === "deterministic" ? "tier0" : "tier2";
}
