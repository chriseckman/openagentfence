/**
 * Per-surface network enforcement capability (OAF-CORE-017, ARCHITECTURE §9).
 * Each surface is `enforced`, `observed_only`, or `unavailable`. Observation
 * alone can never be promoted to enforced, and a truthful adapter reports its
 * empirical capability per configuration/version.
 */
export const NETWORK_SURFACES = [
  "navigation",
  "redirect",
  "form",
  "fetch",
  "headers",
  "websocket",
  "send_beacon",
  "service_worker",
  "upload",
  "download",
  "popup",
  "webmcp",
] as const;

export type NetworkSurface = (typeof NETWORK_SURFACES)[number];

export const ENFORCEMENT_LEVELS = ["enforced", "observed_only", "unavailable"] as const;

export type EnforcementLevel = (typeof ENFORCEMENT_LEVELS)[number];

export type NetworkCapabilities = Readonly<Record<NetworkSurface, EnforcementLevel>>;

/** Conservative default: nothing is enforced until an adapter proves otherwise. */
export const DEFAULT_NETWORK_CAPABILITIES: NetworkCapabilities = Object.freeze({
  navigation: "unavailable",
  redirect: "unavailable",
  form: "unavailable",
  fetch: "unavailable",
  headers: "unavailable",
  websocket: "unavailable",
  send_beacon: "unavailable",
  service_worker: "unavailable",
  upload: "unavailable",
  download: "unavailable",
  popup: "unavailable",
  webmcp: "unavailable",
});
