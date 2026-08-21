import { stableSerialize } from "../action/state-fingerprint.js";
import {
  validateDataProvenance,
  type DataProvenance,
  type ProvenancedDatum,
} from "../contracts/provenance.js";
import { hash } from "../trace/redact.js";

export const MEMORY_ITEM_SCHEMA_VERSION = "1.0.0";
export const MAX_MEMORY_CONTENT_BYTES = 100 * 1024;
export const MAX_MEMORY_MARKERS = 16;

export const MEMORY_SENSITIVITIES = ["none", "sensitive", "secret"] as const;
export type MemorySensitivity = (typeof MEMORY_SENSITIVITIES)[number];

export const MEMORY_MARKERS = ["instruction_removed", "sensitive_value_replaced"] as const;
export type MemoryMarker = (typeof MEMORY_MARKERS)[number];

export interface MemoryWriteCandidate {
  readonly content: string;
  readonly provenance: DataProvenance;
}

/** Closed, versioned item returned for application-owned persistence. */
export interface StoredMemoryItem {
  readonly schemaVersion: typeof MEMORY_ITEM_SCHEMA_VERSION;
  readonly kind: "data";
  readonly content: string;
  /** Original write provenance; read-time memory trust is a separate wrapper. */
  readonly provenance: DataProvenance;
  /** SHA-256 over the canonical item fields other than this hash. */
  readonly contentHash: string;
  readonly sensitivity: MemorySensitivity;
  readonly markers: readonly MemoryMarker[];
}

const CANDIDATE_KEYS = ["content", "provenance"] as const;
const ITEM_KEYS = [
  "schemaVersion",
  "kind",
  "content",
  "provenance",
  "contentHash",
  "sensitivity",
  "markers",
] as const;

export function validateMemoryWriteCandidate(input: unknown): MemoryWriteCandidate | null {
  const record = dataRecord(input, CANDIDATE_KEYS);
  if (record === null) return null;
  const content = boundedContent(record["content"]);
  const provenance = validateDataProvenance(record["provenance"]);
  if (content === null || provenance === null) return null;
  return Object.freeze({ content, provenance });
}

/** Detect the bounded-content case without evaluating accessors or custom prototypes. */
export function memoryWriteCandidateExceedsBounds(input: unknown): boolean {
  const record = dataRecord(input, CANDIDATE_KEYS);
  return (
    record !== null &&
    typeof record["content"] === "string" &&
    Buffer.byteLength(record["content"], "utf8") > MAX_MEMORY_CONTENT_BYTES
  );
}

/** Validate the closed stored shape and its canonical integrity hash. */
export function validateStoredMemoryItem(input: unknown): StoredMemoryItem | null {
  const shaped = validateStoredMemoryItemShape(input);
  if (shaped === null || memoryItemHash(shaped) !== shaped.contentHash) return null;
  return shaped;
}

export function createStoredMemoryItem(input: {
  readonly content: string;
  readonly provenance: DataProvenance;
  readonly sensitivity: MemorySensitivity;
  readonly markers?: readonly MemoryMarker[];
}): StoredMemoryItem {
  const content = boundedContent(input.content);
  const provenance = validateDataProvenance(input.provenance);
  const markers = validateMarkers(input.markers ?? []);
  if (
    content === null ||
    provenance === null ||
    !MEMORY_SENSITIVITIES.includes(input.sensitivity) ||
    markers === null
  ) {
    throw new TypeError("invalid bounded memory item");
  }
  const fields = {
    schemaVersion: MEMORY_ITEM_SCHEMA_VERSION as typeof MEMORY_ITEM_SCHEMA_VERSION,
    kind: "data" as const,
    content,
    provenance,
    sensitivity: input.sensitivity,
    markers,
  };
  return Object.freeze({ ...fields, contentHash: memoryItemHash(fields) });
}

export function memoryItemHash(
  item: Pick<
    StoredMemoryItem,
    "schemaVersion" | "kind" | "content" | "provenance" | "sensitivity" | "markers"
  >,
): string {
  return hash(
    stableSerialize({
      schemaVersion: item.schemaVersion,
      kind: item.kind,
      content: item.content,
      provenance: item.provenance,
      sensitivity: item.sensitivity,
      markers: item.markers,
    }),
  );
}

export function memoryReadDatum(item: StoredMemoryItem): ProvenancedDatum<string> {
  return Object.freeze({
    value: item.content,
    provenance: Object.freeze({ ...item.provenance, trust: "memory" as const }),
  });
}

/** Shape-only validation used to distinguish malformed from hash-tampered reads. */
export function validateStoredMemoryItemShape(input: unknown): StoredMemoryItem | null {
  const record = dataRecord(input, ITEM_KEYS);
  if (record === null) return null;
  if (record["schemaVersion"] !== MEMORY_ITEM_SCHEMA_VERSION || record["kind"] !== "data") {
    return null;
  }
  const content = boundedContent(record["content"]);
  const provenance = validateDataProvenance(record["provenance"]);
  const contentHash = record["contentHash"];
  const sensitivity = record["sensitivity"];
  const markers = validateMarkers(record["markers"]);
  if (
    content === null ||
    provenance === null ||
    typeof contentHash !== "string" ||
    !/^[a-f0-9]{64}$/.test(contentHash) ||
    !MEMORY_SENSITIVITIES.includes(sensitivity as MemorySensitivity) ||
    markers === null
  ) {
    return null;
  }
  return Object.freeze({
    schemaVersion: MEMORY_ITEM_SCHEMA_VERSION,
    kind: "data",
    content,
    provenance,
    contentHash,
    sensitivity: sensitivity as MemorySensitivity,
    markers,
  });
}

function boundedContent(value: unknown): string | null {
  return typeof value === "string" && Buffer.byteLength(value, "utf8") <= MAX_MEMORY_CONTENT_BYTES
    ? value
    : null;
}

function validateMarkers(value: unknown): readonly MemoryMarker[] | null {
  if (!Array.isArray(value) || value.length > MAX_MEMORY_MARKERS) return null;
  const markers: MemoryMarker[] = [];
  for (const marker of value) {
    if (
      !MEMORY_MARKERS.includes(marker as MemoryMarker) ||
      markers.includes(marker as MemoryMarker)
    ) {
      return null;
    }
    markers.push(marker as MemoryMarker);
  }
  return Object.freeze(markers);
}

function dataRecord(
  input: unknown,
  allowedKeys: readonly string[],
): Record<string, unknown> | null {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return null;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Object.keys(descriptors);
  if (
    keys.some((key) => !allowedKeys.includes(key)) ||
    allowedKeys.some((key) => !Object.prototype.hasOwnProperty.call(descriptors, key)) ||
    keys.some((key) => descriptors[key]?.get !== undefined || descriptors[key]?.set !== undefined)
  ) {
    return null;
  }
  const output: Record<string, unknown> = {};
  for (const key of keys) output[key] = descriptors[key]?.value;
  return output;
}
