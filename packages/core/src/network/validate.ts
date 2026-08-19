import {
  ENFORCEMENT_LEVELS,
  NETWORK_SURFACES,
  type EnforcementLevel,
  type NetworkCapabilities,
} from "./capabilities.js";
import { NETWORK_INITIATORS, type NetworkInitiator } from "./initiator.js";
import type { NetworkMutation, NetworkRequestMetadata } from "./mutation.js";

/**
 * Runtime validation for network mutations and capability matrices (OAF-CORE-017,
 * TB6/INV-16). Mutations are untrusted data from adapters; strict, bounded
 * validation rejects malformed/oversized metadata before it reaches the guard,
 * and capability matrices cannot claim a surface absent or promote
 * observation to enforcement.
 */
const MUTATION_KEYS = new Set([
  "surface",
  "initiator",
  "origin",
  "frameOrigin",
  "destination",
  "enforcement",
  "metadata",
  "actionIntentId",
  "redirectHops",
]);
const METADATA_KEYS = new Set(["method", "headers", "bodyHash", "bodySize"]);

const MAX_URL_LENGTH = 4096;
const MAX_ORIGIN_LENGTH = 2048;
const MAX_METHOD_LENGTH = 16;
const MAX_HEADER_KEYS = 50;
const MAX_HEADER_KEY_LENGTH = 128;
const MAX_HEADER_VALUE_LENGTH = 2048;
const MAX_INTENT_ID_LENGTH = 128;
const HEX64 = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      return false;
    }
  }
  return true;
}

function isIn(value: unknown, allowed: readonly string[]): boolean {
  return typeof value === "string" && allowed.includes(value);
}

function validateMetadata(value: unknown): NetworkRequestMetadata | null {
  if (!isRecord(value) || !hasOnlyKeys(value, METADATA_KEYS)) {
    return null;
  }
  const method = value["method"];
  if (
    method !== undefined &&
    (typeof method !== "string" || method.length === 0 || method.length > MAX_METHOD_LENGTH)
  ) {
    return null;
  }
  const headers = value["headers"];
  if (!isRecord(headers)) {
    return null;
  }
  if (Object.keys(headers).length > MAX_HEADER_KEYS) {
    return null;
  }
  const builtHeaders: Record<string, string> = {};
  for (const [key, headerValue] of Object.entries(headers)) {
    if (
      key.length === 0 ||
      key.length > MAX_HEADER_KEY_LENGTH ||
      typeof headerValue !== "string" ||
      headerValue.length > MAX_HEADER_VALUE_LENGTH
    ) {
      return null;
    }
    builtHeaders[key] = headerValue;
  }
  const bodyHash = value["bodyHash"];
  if (bodyHash !== undefined && (typeof bodyHash !== "string" || !HEX64.test(bodyHash))) {
    return null;
  }
  const bodySize = value["bodySize"];
  if (
    bodySize !== undefined &&
    (typeof bodySize !== "number" || !Number.isInteger(bodySize) || bodySize < 0)
  ) {
    return null;
  }
  return {
    ...(method !== undefined ? { method } : {}),
    headers: Object.freeze(builtHeaders),
    ...(bodyHash !== undefined ? { bodyHash } : {}),
    ...(bodySize !== undefined ? { bodySize } : {}),
  };
}

/** Strict, bounded validation of a `NetworkMutation`. */
export function validateNetworkMutation(input: unknown): NetworkMutation | null {
  if (!isRecord(input) || !hasOnlyKeys(input, MUTATION_KEYS)) {
    return null;
  }
  if (!isIn(input["surface"], NETWORK_SURFACES)) {
    return null;
  }
  if (!isIn(input["initiator"], NETWORK_INITIATORS)) {
    return null;
  }
  if (!isIn(input["enforcement"], ENFORCEMENT_LEVELS)) {
    return null;
  }
  const destination = input["destination"];
  if (
    typeof destination !== "string" ||
    destination.length === 0 ||
    destination.length > MAX_URL_LENGTH
  ) {
    return null;
  }
  for (const key of ["origin", "frameOrigin"]) {
    const field = input[key];
    if (
      field !== undefined &&
      (typeof field !== "string" || field.length === 0 || field.length > MAX_ORIGIN_LENGTH)
    ) {
      return null;
    }
  }
  const intentId = input["actionIntentId"];
  if (
    intentId !== undefined &&
    (typeof intentId !== "string" ||
      intentId.length === 0 ||
      intentId.length > MAX_INTENT_ID_LENGTH)
  ) {
    return null;
  }
  const redirectHops = input["redirectHops"];
  if (
    redirectHops !== undefined &&
    (typeof redirectHops !== "number" ||
      !Number.isInteger(redirectHops) ||
      redirectHops < 0 ||
      redirectHops > 100)
  ) {
    return null;
  }
  const metadata = input["metadata"];
  const validatedMetadata = metadata === undefined ? null : validateMetadata(metadata);
  if (metadata !== undefined && validatedMetadata === null) {
    return null;
  }
  return Object.freeze({
    surface: input["surface"] as NetworkMutation["surface"],
    initiator: input["initiator"] as NetworkInitiator,
    ...(input["origin"] !== undefined ? { origin: input["origin"] as string } : {}),
    ...(input["frameOrigin"] !== undefined ? { frameOrigin: input["frameOrigin"] as string } : {}),
    destination,
    enforcement: input["enforcement"] as EnforcementLevel,
    ...(validatedMetadata !== null ? { metadata: validatedMetadata } : {}),
    ...(intentId !== undefined ? { actionIntentId: intentId } : {}),
    ...(redirectHops !== undefined ? { redirectHops } : {}),
  });
}

/** Validate a per-surface capability matrix; every surface must be present. */
export function validateNetworkCapabilities(input: unknown): NetworkCapabilities | null {
  if (!isRecord(input)) {
    return null;
  }
  for (const surface of NETWORK_SURFACES) {
    if (!isIn(input[surface], ENFORCEMENT_LEVELS)) {
      return null;
    }
  }
  for (const key of Object.keys(input)) {
    if (!(NETWORK_SURFACES as readonly string[]).includes(key)) {
      return null;
    }
  }
  const built: Record<string, EnforcementLevel> = {};
  for (const surface of NETWORK_SURFACES) {
    built[surface] = input[surface] as EnforcementLevel;
  }
  return Object.freeze(built);
}
