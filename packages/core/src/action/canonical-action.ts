import type { DataProvenance, ProvenancedDatum } from "../contracts/provenance.js";

export const ACTION_TYPES = [
  "READ",
  "SCROLL",
  "CLICK",
  "TYPE",
  "FILL",
  "NAVIGATE",
  "SUBMIT",
  "UPLOAD",
  "DOWNLOAD",
  "OPEN_TAB",
  "CLOSE_TAB",
  "COPY",
  "PASTE",
  "EXECUTE_SCRIPT",
  "AUTHENTICATE",
  "PURCHASE",
  "DELETE",
  "PUBLISH",
  "MESSAGE",
  "CHANGE_SETTING",
  "UNKNOWN",
] as const;

export type ActionType = (typeof ACTION_TYPES)[number];

export const SIDE_EFFECT_CLASSES = [
  "READ_ONLY",
  "REVERSIBLE",
  "EXTERNAL_SIDE_EFFECT",
  "FINANCIAL",
  "DESTRUCTIVE",
  "SECURITY_SENSITIVE",
] as const;

export type SideEffectClass = (typeof SIDE_EFFECT_CLASSES)[number];

export interface ActionTarget {
  readonly element?: string;
  readonly frame?: string;
  readonly origin?: string;
}

/**
 * Framework-neutral action (PRD §13.7). `raw` holds the framework-specific
 * operation reference; adapters normalize into this shape before authorization.
 */
export interface CanonicalAction {
  readonly type: ActionType;
  /** Trusted origin of a NAVIGATE action; absent values are treated as direct. */
  readonly navigationOrigin?: "link" | "direct";
  readonly target?: ActionTarget;
  readonly destination?: string;
  /** Security-relevant action data retains its source across authorization. */
  readonly data?: ProvenancedDatum;
  readonly instructionProvenance: DataProvenance;
  readonly sideEffectClass?: SideEffectClass;
  readonly raw?: unknown;
}
