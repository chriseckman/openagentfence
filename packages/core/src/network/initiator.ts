/**
 * Initiators of network effects (OAF-CORE-017, INV-21). A mutation records its
 * actual initiator; correlation to an authorized action is only ever
 * `authorized_action` when it is proven, and temporal proximity is never proof.
 */
export const NETWORK_INITIATORS = [
  "authorized_action",
  "page_script",
  "form",
  "redirect",
  "webmcp",
  "service_worker",
  "unknown",
] as const;

export type NetworkInitiator = (typeof NETWORK_INITIATORS)[number];
