import type { CanonicalAction } from "./canonical-action.js";
import { fingerprint, stableSerialize } from "./state-fingerprint.js";

/** Identity of the observation the intent was bound to (ADR-0010, INV-19). */
export interface ObservationIdentity {
  readonly browserContextId: string;
  readonly pageId: string;
  readonly revision: number;
}

/** Identity of the action target, captured from the observation. */
export interface TargetIdentity {
  readonly selector?: string;
  readonly element?: string;
  readonly frame?: string;
  readonly origin?: string;
}

/**
 * A framework-neutral snapshot binding a canonical action to the exact page
 * and target state that authorization inspected (ADR-0010). It contains no raw
 * secret and no framework object. Any security-relevant field change, policy
 * hash change, operation change, or expiry invalidates the authorization.
 */
export interface ActionIntent {
  readonly intentId: string;
  readonly actionId: string;
  readonly action: CanonicalAction;
  readonly observation: ObservationIdentity;
  readonly target: TargetIdentity;
  readonly frameOrigin?: string;
  readonly destination?: string;
  readonly navigationOrigin?: "link" | "direct";
  readonly formAction?: string;
  readonly securityAttributes: Readonly<Record<string, string>>;
  readonly visibility: string;
  readonly policyHash: string;
  readonly operationHash: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export type IntentMismatchCode =
  | "observation"
  | "target"
  | "frame"
  | "origin"
  | "destination"
  | "navigation_origin"
  | "form_action"
  | "security_attributes"
  | "visibility"
  | "operation"
  | "policy";

const INTENT_KEYS: readonly string[] = [
  "intentId",
  "actionId",
  "action",
  "observation",
  "target",
  "frameOrigin",
  "destination",
  "navigationOrigin",
  "formAction",
  "securityAttributes",
  "visibility",
  "policyHash",
  "operationHash",
  "createdAt",
  "expiresAt",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) {
      return false;
    }
  }
  return true;
}

function validateStringMap(value: unknown): Readonly<Record<string, string>> | null {
  if (!isRecord(value)) {
    return null;
  }
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== "string") {
      return null;
    }
    out[key] = item;
  }
  return Object.freeze(out);
}

function validateObservation(value: unknown): ObservationIdentity | null {
  if (!isRecord(value) || !hasOnlyKeys(value, ["browserContextId", "pageId", "revision"])) {
    return null;
  }
  const { browserContextId, pageId, revision } = value;
  if (typeof browserContextId !== "string" || typeof pageId !== "string") {
    return null;
  }
  if (typeof revision !== "number" || !Number.isInteger(revision) || revision < 0) {
    return null;
  }
  return { browserContextId, pageId, revision };
}

function validateTarget(value: unknown): TargetIdentity | null {
  if (!isRecord(value) || !hasOnlyKeys(value, ["selector", "element", "frame", "origin"])) {
    return null;
  }
  for (const key of ["selector", "element", "frame", "origin"]) {
    const field = value[key];
    if (field !== undefined && typeof field !== "string") {
      return null;
    }
  }
  return {
    ...(typeof value["selector"] === "string" ? { selector: value["selector"] } : {}),
    ...(typeof value["element"] === "string" ? { element: value["element"] } : {}),
    ...(typeof value["frame"] === "string" ? { frame: value["frame"] } : {}),
    ...(typeof value["origin"] === "string" ? { origin: value["origin"] } : {}),
  };
}

/** Runtime validation of an `ActionIntent` (strict, bounded). */
export function validateActionIntent(input: unknown): ActionIntent | null {
  if (!isRecord(input) || !hasOnlyKeys(input, INTENT_KEYS)) {
    return null;
  }
  const intentId = input["intentId"];
  const actionId = input["actionId"];
  const visibility = input["visibility"];
  const policyHash = input["policyHash"];
  const operationHash = input["operationHash"];
  if (
    typeof intentId !== "string" ||
    intentId.length === 0 ||
    typeof actionId !== "string" ||
    actionId.length === 0 ||
    typeof visibility !== "string" ||
    typeof policyHash !== "string" ||
    typeof operationHash !== "string"
  ) {
    return null;
  }
  const observation = validateObservation(input["observation"]);
  if (observation === null) {
    return null;
  }
  const target = validateTarget(input["target"]);
  if (target === null) {
    return null;
  }
  if (!isRecord(input["action"])) {
    return null;
  }
  for (const key of ["frameOrigin", "destination", "navigationOrigin", "formAction"]) {
    const field = input[key];
    if (field !== undefined && typeof field !== "string") {
      return null;
    }
  }
  if (
    input["navigationOrigin"] !== undefined &&
    input["navigationOrigin"] !== "link" &&
    input["navigationOrigin"] !== "direct"
  ) {
    return null;
  }
  const securityAttributes = validateStringMap(input["securityAttributes"]);
  if (securityAttributes === null) {
    return null;
  }
  const createdAt = input["createdAt"];
  const expiresAt = input["expiresAt"];
  if (
    typeof createdAt !== "number" ||
    typeof expiresAt !== "number" ||
    !Number.isFinite(createdAt) ||
    !Number.isFinite(expiresAt)
  ) {
    return null;
  }
  return Object.freeze({
    intentId,
    actionId,
    action: input["action"] as unknown as CanonicalAction,
    observation,
    target,
    ...(input["frameOrigin"] !== undefined ? { frameOrigin: input["frameOrigin"] as string } : {}),
    ...(input["destination"] !== undefined ? { destination: input["destination"] as string } : {}),
    ...(input["navigationOrigin"] !== undefined
      ? { navigationOrigin: input["navigationOrigin"] }
      : {}),
    ...(input["formAction"] !== undefined ? { formAction: input["formAction"] as string } : {}),
    securityAttributes,
    visibility,
    policyHash,
    operationHash,
    createdAt,
    expiresAt,
  });
}

/** The bound state used for fingerprints — excludes ids/timestamps. */
export function intentBoundState(intent: ActionIntent): Record<string, unknown> {
  return {
    observation: intent.observation,
    target: intent.target,
    frameOrigin: intent.frameOrigin ?? null,
    destination: intent.destination ?? null,
    navigationOrigin: intent.navigationOrigin ?? "direct",
    formAction: intent.formAction ?? null,
    securityAttributes: intent.securityAttributes,
    visibility: intent.visibility,
    policyHash: intent.policyHash,
    operationHash: intent.operationHash,
  };
}

/** Deterministic fingerprint of the security-relevant bound state. */
export function computeIntentFingerprint(intent: ActionIntent): string {
  return fingerprint(intentBoundState(intent));
}

/** True when the intent has expired at `now` (exclusive). */
export function isIntentExpired(intent: ActionIntent, now: number = Date.now()): boolean {
  return now >= intent.expiresAt;
}

/** The re-resolved current state an adapter compares against the bound intent. */
export interface IntentStateSnapshot {
  readonly observation: ObservationIdentity;
  readonly target: TargetIdentity;
  readonly frameOrigin?: string;
  readonly destination?: string;
  readonly navigationOrigin?: "link" | "direct";
  readonly formAction?: string;
  readonly securityAttributes: Readonly<Record<string, string>>;
  readonly visibility: string;
  readonly policyHash: string;
  readonly operationHash: string;
}

/**
 * Deterministic comparison of the re-resolved current state against the bound
 * intent. Returns the list of stable mismatch codes; an empty list means the
 * state still matches. The bound intent is never mutated (ADR-0010).
 */
export function compareIntentState(
  intent: ActionIntent,
  snapshot: IntentStateSnapshot,
): readonly IntentMismatchCode[] {
  const mismatches: IntentMismatchCode[] = [];
  const bound = intentBoundState(intent);
  const current: Record<string, unknown> = {
    observation: snapshot.observation,
    target: snapshot.target,
    frameOrigin: snapshot.frameOrigin ?? null,
    destination: snapshot.destination ?? null,
    navigationOrigin: snapshot.navigationOrigin ?? "direct",
    formAction: snapshot.formAction ?? null,
    securityAttributes: snapshot.securityAttributes,
    visibility: snapshot.visibility,
    policyHash: snapshot.policyHash,
    operationHash: snapshot.operationHash,
  };
  const fields: readonly [string, IntentMismatchCode][] = [
    ["observation", "observation"],
    ["target", "target"],
    ["frameOrigin", "frame"],
    ["destination", "destination"],
    ["navigationOrigin", "navigation_origin"],
    ["formAction", "form_action"],
    ["securityAttributes", "security_attributes"],
    ["visibility", "visibility"],
    ["policyHash", "policy"],
    ["operationHash", "operation"],
  ];
  for (const [field, code] of fields) {
    if (stableSerialize(bound[field]) !== stableSerialize(current[field])) {
      mismatches.push(code);
    }
  }
  return mismatches;
}
