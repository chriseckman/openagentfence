import type { DataProvenance } from "../contracts/provenance.js";
import type { ProbeResult } from "../probe/probe-result.js";

export interface FrameInfo {
  /** Adapter-stable opaque identity, not page-controlled data. */
  readonly id?: string;
  readonly url: string;
  readonly origin: string;
  readonly frameOrigin?: string;
  /** Validated probe output for an accessible frame; absent when embedded. */
  readonly probe?: ProbeResult;
  /** True when the frame's content could not be inspected (cross-origin). */
  readonly embedded?: boolean;
}

/**
 * Framework-neutral observation of a page (PRD §16-17, ARCHITECTURE §5).
 * All observation data is untrusted (TB2) and labelled `trust: web` at
 * construction.
 */
export interface PageObservation {
  /** Adapter-stable opaque page and context identities. */
  readonly pageId?: string;
  readonly contextId?: string;
  /** Monotonic adapter-local revision. */
  readonly revision?: number;
  readonly url: string;
  readonly origin: string;
  readonly title?: string;
  readonly frames: readonly FrameInfo[];
  readonly probe?: ProbeResult;
  readonly ariaSnapshot?: string;
  readonly screenshot?: unknown;
  readonly provenance: DataProvenance;
}
