import type { ResolvedCapabilities } from "./envelope.js";

/**
 * Secure defaults (PRD §13.6): reads allowed; navigation within trusted scope;
 * credential use restricted; uploads, purchases, destructive actions, external
 * communication, arbitrary JavaScript, and private-network access denied.
 */
export const SECURE_DEFAULT_CAPABILITIES: ResolvedCapabilities = {
  navigation: "same-site",
  downloads: false,
  uploads: false,
  purchases: false,
  messaging: false,
  destructiveActions: false,
  credentials: false,
  executeScript: false,
  privateNetwork: false,
  externalCommunication: false,
};
