import type { ScannerVerdict } from "./verdict.js";
import type { Finding, Severity } from "./finding.js";
import type { SanitizationSpan } from "../orchestrator/sanitize.js";
import type { ProvenancedDatum } from "./provenance.js";

export interface ScanResult {
  readonly scanner: string;
  readonly kind: "deterministic" | "semantic";
  readonly verdict: ScannerVerdict;
  readonly severity: Severity;
  readonly confidence?: number;
  readonly findings: readonly Finding[];
  /** Whole-text sanitized reconstruction (replaces the input). */
  readonly sanitized?: ProvenancedDatum<string>;
  /** Span-level redactions applied sequentially; removal wins overlaps. */
  readonly sanitizations?: readonly SanitizationSpan[];
  /** `timed_out` results are recorded as such, never as `allow`. */
  readonly timedOut?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}
