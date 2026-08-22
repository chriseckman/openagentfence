import type { NetworkCapabilities } from "../network/capabilities.js";

/**
 * Capability flags an adapter exposes so `core` and `doctor` can report
 * enforcement gaps (Q9, THREAT_MODEL §9). A flag of `false` means the adapter
 * cannot enforce that surface; this is a documented gap, not silent coverage.
 */
export interface BrowserAdapterCapabilities {
  readonly route: boolean;
  /** Exact per-surface matrix for this adapter instance/configuration. */
  readonly network: NetworkCapabilities;
  /** Top-level navigation event capture for bounded POST_ACTION validation. */
  readonly navigationEvents: boolean;
  readonly downloadEvents: boolean;
  readonly popupEvents: boolean;
  readonly screenshot: boolean;
  readonly ariaSnapshot: boolean;
}
