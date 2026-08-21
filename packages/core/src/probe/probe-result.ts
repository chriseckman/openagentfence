import type { BoundingBox } from "../contracts/finding.js";

export interface ProbeNode {
  readonly selector: string;
  readonly tagName: string;
  readonly text: string;
  readonly display: string;
  readonly visibility: string;
  readonly opacity: number;
  readonly ariaHidden: boolean;
  readonly hidden: boolean;
  readonly role: string | null;
  readonly ariaLabel: string | null;
  readonly ariaDescription: string | null;
  readonly attributes: Readonly<Record<string, string>>;
  readonly dimensions: BoundingBox | null;
  readonly boundingBox: BoundingBox | null;
  readonly frameOrigin: string;
  /** Visual/geometry signals captured for the out-of-page classifier. */
  readonly fontSize: string | null;
  readonly color: string | null;
  readonly backgroundColor: string | null;
  readonly position: string | null;
  readonly transform: string | null;
  readonly clipPath: string | null;
  readonly overflow: string | null;
  readonly inViewport: boolean;
  readonly pseudoBefore: string | null;
  readonly pseudoAfter: string | null;
}

export interface ProbeMetadata {
  readonly title: string;
  readonly meta: Readonly<Record<string, string>>;
  readonly jsonLd: readonly string[];
  readonly noscript: readonly string[];
}

export interface ProbeLink {
  readonly text: string;
  readonly href: string;
}

/** Per-category truncation flags so limits are explicit, never silent (INV-09). */
export interface ProbeTruncation {
  readonly nodes: boolean;
  readonly textBytes: boolean;
  readonly comments: boolean;
  readonly metadata: boolean;
  readonly links: boolean;
  readonly time: boolean;
}

/**
 * Typed output of the in-page probe (OAF-CORE-014). The probe collects
 * *signals only*; classification happens out-of-page (OAF-BROWSER-005). The
 * output is untrusted (TB2) and must cross `validateProbeResult` before use.
 */
export interface ProbeResult {
  readonly probeVersion: number;
  readonly truncated: boolean;
  readonly truncation: ProbeTruncation;
  readonly nodes: readonly ProbeNode[];
  readonly comments: readonly string[];
  readonly metadata: ProbeMetadata;
  readonly links: readonly ProbeLink[];
}

export const PROBE_VERSION = 2;

/**
 * Contrast ratio is not computed by the probe: only the raw `color` and
 * `backgroundColor` inputs are captured. A conservative fallback treats
 * unreadable contrast as low-confidence in the out-of-page classifier.
 */
export const PROBE_CONTRAST_UNSUPPORTED = true;
