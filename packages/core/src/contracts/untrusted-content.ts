import { hash } from "../trace/redact.js";
import type { DataProvenance, TrustLevel } from "./provenance.js";

/**
 * Sanitized, provenance-preserving wrapper for untrusted page/tool/memory
 * content (OAF-CORE-016, INV-13/20). The wrapped content is permanently
 * `instructionEligible: false`: no downstream consumer may treat it as an
 * instruction source, regardless of what the text says. Provenance, a content
 * hash, a revision, and truncation metadata survive sanitization.
 */
export interface UntrustedContent {
  readonly content: string;
  readonly provenance: DataProvenance;
  readonly contentHash: string;
  readonly revision: number;
  readonly truncated: boolean;
  readonly instructionEligible: false;
}

export interface UntrustedContentInput {
  readonly content: string;
  readonly provenance: DataProvenance;
  readonly revision?: number;
  readonly truncated?: boolean;
}

const UNTRUSTED_TRUST: readonly TrustLevel[] = ["web", "tool", "memory"];
const MAX_CONTENT_LENGTH = 1_000_000;
const CONTENT_KEYS: readonly string[] = [
  "content",
  "provenance",
  "contentHash",
  "revision",
  "truncated",
  "instructionEligible",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateUntrustedProvenance(value: unknown): DataProvenance | null {
  if (!isRecord(value)) {
    return null;
  }
  const trust = value["trust"];
  if (typeof trust !== "string" || !UNTRUSTED_TRUST.includes(trust as TrustLevel)) {
    return null;
  }
  const out: Record<string, unknown> = { trust };
  for (const key of ["origin", "frameOrigin", "pageId", "elementId", "timestamp"]) {
    const field = value[key];
    if (field !== undefined) {
      if (typeof field !== "string") {
        return null;
      }
      out[key] = field;
    }
  }
  return out as unknown as DataProvenance;
}

/** Runtime validation of untrusted content (strict, unknown-key rejection). */
export function validateUntrustedContent(input: unknown): UntrustedContent | null {
  if (!isRecord(input)) {
    return null;
  }
  for (const key of Object.keys(input)) {
    if (!CONTENT_KEYS.includes(key)) {
      return null;
    }
  }
  const content = input["content"];
  if (typeof content !== "string" || content.length > MAX_CONTENT_LENGTH) {
    return null;
  }
  const provenance = validateUntrustedProvenance(input["provenance"]);
  if (provenance === null) {
    return null;
  }
  const contentHash = input["contentHash"];
  if (typeof contentHash !== "string" || contentHash.length === 0) {
    return null;
  }
  const revision = input["revision"];
  if (typeof revision !== "number" || !Number.isInteger(revision) || revision < 0) {
    return null;
  }
  const truncated = input["truncated"];
  if (typeof truncated !== "boolean") {
    return null;
  }
  if (input["instructionEligible"] !== false) {
    return null;
  }
  return Object.freeze({
    content,
    provenance,
    contentHash,
    revision,
    truncated,
    instructionEligible: false as const,
  });
}

/**
 * Wrap sanitized untrusted content with original provenance and a content hash.
 * `instructionEligible` is a type-level constant `false` and can never be set.
 */
export function wrapUntrustedContent(input: UntrustedContentInput): UntrustedContent {
  const content = input.content;
  if (typeof content !== "string" || content.length > MAX_CONTENT_LENGTH) {
    throw new TypeError("untrusted content must be a bounded string");
  }
  const provenance = validateUntrustedProvenance(input.provenance);
  if (provenance === null) {
    throw new TypeError("untrusted content provenance must be web, tool, or memory trust");
  }
  const revision = input.revision ?? 0;
  if (!Number.isInteger(revision) || revision < 0) {
    throw new TypeError("untrusted content revision must be a non-negative integer");
  }
  return Object.freeze({
    content,
    provenance,
    contentHash: hash(content),
    revision,
    truncated: input.truncated ?? false,
    instructionEligible: false as const,
  });
}
