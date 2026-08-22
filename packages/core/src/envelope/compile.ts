import { SECURE_DEFAULT_CAPABILITIES } from "./defaults.js";
import type {
  ActionShape,
  CapabilityEnvelope,
  EnvelopeEvaluation,
  EnvelopeNarrowing,
  ResolvedCapabilities,
} from "./envelope.js";
import type { NavigationMode, ValidatedTaskContract } from "../contracts/task-contract.js";
import { isValidatedTaskContract } from "../contracts/task-contract.js";
import type { ActionType } from "../action/canonical-action.js";
import { REASON_CODES, type ReasonCode } from "../policy/reasons.js";
import { originOf, sameOrigin, sameSite } from "../action/url.js";
import { isSupportedNetworkScheme } from "../network/destination.js";
import { isPrivateNetworkDestination } from "../network/private-network.js";

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

const NAVIGATION_STRICTNESS: Record<NavigationMode, number> = {
  none: 0,
  "same-origin": 1,
  "same-site": 2,
  allowlist: 3,
};

const CAPABILITY_FOR_ACTION: Partial<Record<ActionType, keyof ResolvedCapabilities>> = {
  UPLOAD: "uploads",
  SUBMIT: "externalCommunication",
  PURCHASE: "purchases",
  EXECUTE_SCRIPT: "executeScript",
  DOWNLOAD: "downloads",
  MESSAGE: "messaging",
  PUBLISH: "messaging",
  DELETE: "destructiveActions",
  CHANGE_SETTING: "destructiveActions",
  AUTHENTICATE: "credentials",
};

/**
 * Compile a validated `TaskContract` constrained by secure defaults into a
 * frozen, immutable `CapabilityEnvelope` (ARCHITECTURE §4). The compiler
 * accepts only a `ValidatedTaskContract` (produced by `validateTaskContract`);
 * it never receives a policy document, profile object, provider configuration,
 * or credential, and it fails safely at runtime for JS callers that bypass the
 * type boundary (INV-01, INV-12, INV-16, TB1).
 */
export function compileTaskContract(contract: ValidatedTaskContract): CapabilityEnvelope {
  if (!isValidatedTaskContract(contract)) {
    throw new TypeError("compileTaskContract requires a validated TaskContract");
  }
  const caps: Mutable<ResolvedCapabilities> = { ...SECURE_DEFAULT_CAPABILITIES };
  const requested = contract.capabilities;
  if (requested !== undefined) {
    if (requested.navigation !== undefined) {
      caps.navigation = requested.navigation;
    }
    if (requested.downloads === true) {
      caps.downloads = true;
    }
    if (requested.uploads === true) {
      caps.uploads = true;
    }
    if (requested.purchases === true) {
      caps.purchases = true;
    }
    if (requested.messaging === true) {
      caps.messaging = true;
    }
    if (requested.destructiveActions === true) {
      caps.destructiveActions = true;
    }
    if (requested.credentials === true) {
      caps.credentials = true;
    }
    if (requested.executeScript === true) {
      caps.executeScript = true;
    }
    if (requested.privateNetwork === true) {
      caps.privateNetwork = true;
    }
    if (requested.externalCommunication === true) {
      caps.externalCommunication = true;
    }
  }
  const allowedOrigins = contract.origins?.allow ?? [];
  const blockedOrigins = contract.origins?.block ?? [];
  return createEnvelope(contract.task, caps, allowedOrigins, blockedOrigins);
}

/** Secure-default envelope for a session with no contract (safe by default). */
export function secureDefaultEnvelope(task: string): CapabilityEnvelope {
  return createEnvelope(task, { ...SECURE_DEFAULT_CAPABILITIES }, [], []);
}

function createEnvelope(
  task: string,
  caps: ResolvedCapabilities,
  allowedOrigins: readonly string[],
  blockedOrigins: readonly string[],
): CapabilityEnvelope {
  const envelope: CapabilityEnvelope = {
    task,
    navigation: caps.navigation,
    downloads: caps.downloads,
    uploads: caps.uploads,
    purchases: caps.purchases,
    messaging: caps.messaging,
    destructiveActions: caps.destructiveActions,
    credentials: caps.credentials,
    executeScript: caps.executeScript,
    privateNetwork: caps.privateNetwork,
    externalCommunication: caps.externalCommunication,
    allowedOrigins,
    blockedOrigins,
    evaluate: (action: ActionShape): EnvelopeEvaluation =>
      evaluateCapabilities(caps, allowedOrigins, blockedOrigins, action),
    narrow: (patch: EnvelopeNarrowing): CapabilityEnvelope =>
      createEnvelope(
        task,
        narrowCapabilities(caps, patch),
        narrowOrigins(allowedOrigins, patch.allowedOrigins),
        blockedOrigins,
      ),
  };
  return Object.freeze(envelope);
}

function evaluateCapabilities(
  caps: ResolvedCapabilities,
  allowedOrigins: readonly string[],
  blockedOrigins: readonly string[],
  action: ActionShape,
): EnvelopeEvaluation {
  const reasons: ReasonCode[] = [];

  if (action.type === "UNKNOWN") {
    return { allowed: false, reasons: [REASON_CODES.unknown_action] };
  }

  const required = CAPABILITY_FOR_ACTION[action.type];
  if (required !== undefined && !caps[required]) {
    return { allowed: false, reasons: [REASON_CODES.capability_denied] };
  }

  const destination = action.destination;
  if (destination !== undefined && !isSupportedNetworkScheme(destination)) {
    return { allowed: false, reasons: [REASON_CODES.unsupported_url_scheme] };
  }
  if (
    destination !== undefined &&
    isPrivateNetworkDestination(destination) &&
    !caps.privateNetwork
  ) {
    return { allowed: false, reasons: [REASON_CODES.private_network_destination] };
  }

  if (
    (action.type === "NAVIGATE" || action.type === "SUBMIT" || action.type === "UPLOAD") &&
    destination !== undefined
  ) {
    const allowed = navigationAllowed(
      caps.navigation,
      allowedOrigins,
      blockedOrigins,
      destination,
      action.target?.origin,
    );
    if (!allowed) {
      return { allowed: false, reasons: [REASON_CODES.destination_not_allowed] };
    }
  }

  if (reasons.length > 0) {
    return { allowed: false, reasons };
  }
  return { allowed: true, reasons: [] };
}

function navigationAllowed(
  mode: NavigationMode,
  allowedOrigins: readonly string[],
  blockedOrigins: readonly string[],
  destination: string,
  currentOrigin: string | undefined,
): boolean {
  const destinationOrigin = originOf(destination);
  if (destinationOrigin === null) {
    // Unparseable destination: fail closed.
    return false;
  }
  if (blockedOrigins.includes(destinationOrigin)) return false;
  switch (mode) {
    case "none":
      return false;
    case "same-origin":
      return currentOrigin !== undefined && sameOrigin(destinationOrigin, currentOrigin);
    case "same-site":
      return currentOrigin !== undefined && sameSite(destinationOrigin, currentOrigin);
    case "allowlist":
      return allowedOrigins.includes(destinationOrigin);
  }
}

function narrowCapabilities(
  caps: ResolvedCapabilities,
  patch: EnvelopeNarrowing,
): ResolvedCapabilities {
  const narrowed: Mutable<ResolvedCapabilities> = { ...caps };

  if (patch.navigation !== undefined) {
    const current = NAVIGATION_STRICTNESS[caps.navigation];
    const requested = NAVIGATION_STRICTNESS[patch.navigation];
    narrowed.navigation = requested < current ? patch.navigation : caps.navigation;
  }
  narrowed.downloads = and(caps.downloads, patch.downloads);
  narrowed.uploads = and(caps.uploads, patch.uploads);
  narrowed.purchases = and(caps.purchases, patch.purchases);
  narrowed.messaging = and(caps.messaging, patch.messaging);
  narrowed.destructiveActions = and(caps.destructiveActions, patch.destructiveActions);
  narrowed.credentials = and(caps.credentials, patch.credentials);
  narrowed.executeScript = and(caps.executeScript, patch.executeScript);
  narrowed.privateNetwork = and(caps.privateNetwork, patch.privateNetwork);
  narrowed.externalCommunication = and(caps.externalCommunication, patch.externalCommunication);
  return narrowed;
}

function and(current: boolean, patch: boolean | undefined): boolean {
  return patch === undefined ? current : current && patch;
}

function narrowOrigins(
  current: readonly string[],
  patch: readonly string[] | undefined,
): readonly string[] {
  if (patch === undefined) {
    return current;
  }
  const patchSet = new Set(patch);
  return current.filter((o) => patchSet.has(o));
}

/** Whether an envelope allows every action the other allows (for tests/explain). */
export function envelopeAllowsAtLeast(
  original: CapabilityEnvelope,
  narrowed: CapabilityEnvelope,
): boolean {
  if (NAVIGATION_STRICTNESS[narrowed.navigation] > NAVIGATION_STRICTNESS[original.navigation]) {
    return false;
  }
  const booleans: readonly (keyof ResolvedCapabilities)[] = [
    "downloads",
    "uploads",
    "purchases",
    "messaging",
    "destructiveActions",
    "credentials",
    "executeScript",
    "privateNetwork",
    "externalCommunication",
  ];
  for (const key of booleans) {
    if (narrowed[key] && !original[key]) {
      return false;
    }
  }
  return true;
}
