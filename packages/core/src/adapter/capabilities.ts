/**
 * Capability flags an adapter exposes so `core` and `doctor` can report
 * enforcement gaps (Q9, THREAT_MODEL §9). A flag of `false` means the adapter
 * cannot enforce that surface; this is a documented gap, not silent coverage.
 */
export interface BrowserAdapterCapabilities {
  readonly route: boolean;
  /** Top-level navigation event capture for bounded POST_ACTION validation. */
  readonly navigationEvents: boolean;
  readonly downloadEvents: boolean;
  readonly popupEvents: boolean;
  readonly screenshot: boolean;
  readonly ariaSnapshot: boolean;
}
