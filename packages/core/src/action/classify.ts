import type { CanonicalAction, SideEffectClass } from "./canonical-action.js";
import { detectHandles } from "../secrets/handle-codec.js";
import { originOf, sameOrigin } from "./url.js";

const SIDE_EFFECT_RANK: Record<SideEffectClass, number> = {
  READ_ONLY: 0,
  REVERSIBLE: 1,
  EXTERNAL_SIDE_EFFECT: 2,
  FINANCIAL: 3,
  DESTRUCTIVE: 4,
  SECURITY_SENSITIVE: 5,
};

/**
 * High-impact classification (ARCHITECTURE §6): anything outside READ/SCROLL,
 * or carrying a secret handle, upload, cross-origin destination, or a
 * side-effect class above REVERSIBLE. This is the Action Guard's fail-closed
 * input; unknown framework operations normalize to UNKNOWN and are treated as
 * high impact.
 */
export function isHighImpact(action: CanonicalAction): boolean {
  if (action.type !== "READ" && action.type !== "SCROLL") {
    return true;
  }
  if (action.sideEffectClass !== undefined && SIDE_EFFECT_RANK[action.sideEffectClass] > 1) {
    return true;
  }
  if (detectHandles(action.data).length > 0) {
    return true;
  }
  if (isCrossOrigin(action)) {
    return true;
  }
  return false;
}

/** True when the action's destination points at an origin other than its target's. */
export function isCrossOrigin(action: CanonicalAction): boolean {
  const destination = action.destination;
  if (destination === undefined) {
    return false;
  }
  const destinationOrigin = originOf(destination);
  if (destinationOrigin === null) {
    return false;
  }
  const targetOrigin = action.target?.origin;
  if (targetOrigin === undefined) {
    // No trusted context to compare against: treat as potentially cross-origin.
    return true;
  }
  return !sameOrigin(destinationOrigin, targetOrigin);
}
