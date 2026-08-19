import { readFileSync } from "node:fs";
import { hash, stableSerialize } from "@openagentfence/core";

/**
 * Strict, versioned, adaptive-ready corpus-case contract (OAF-TEST-002). Corpus
 * files are hostile input even though they live in the repository: the loader
 * is bounded in bytes, depth, and case count, rejects unknown fields, and never
 * deserializes executable objects. Cases declare metadata only; they cannot
 * grant capability or modify policy at runtime.
 */

export const CORPUS_SCHEMA_VERSION = "1.0.0";

export type CorpusMode = "attack" | "benign";
export type CorpusKind = "static" | "mutation" | "adaptive-ready";

export interface CorpusPage {
  readonly url: string;
  readonly origin?: string;
}

export interface CorpusExpected {
  readonly outcome: string;
  readonly reasons?: readonly string[];
  readonly findings?: readonly string[];
  readonly risk?: string;
  readonly control?: string;
}

export interface CorpusCase {
  readonly id: string;
  readonly mode: CorpusMode;
  readonly attackClasses: readonly string[];
  readonly invariants: readonly string[];
  readonly kind: CorpusKind;
  readonly surfaces?: readonly string[];
  readonly initiator?: string;
  readonly pages: readonly CorpusPage[];
  readonly task: string;
  readonly policy?: Readonly<Record<string, unknown>>;
  readonly steps?: readonly Readonly<Record<string, unknown>>[];
  readonly expected: CorpusExpected;
  readonly locale?: string;
  readonly tags?: readonly string[];
}

const CASE_KEYS = new Set([
  "id",
  "mode",
  "attackClasses",
  "invariants",
  "kind",
  "surfaces",
  "initiator",
  "pages",
  "task",
  "policy",
  "steps",
  "expected",
  "locale",
  "tags",
]);
const PAGE_KEYS = new Set(["url", "origin"]);
const EXPECTED_KEYS = new Set(["outcome", "reasons", "findings", "risk", "control"]);

const MAX_CASES = 10_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 32;
const MAX_STRING_LENGTH = 65_536;

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

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function boundedString(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_STRING_LENGTH;
}

/** Reject executable/generator or authority-granting metadata fields. */
function rejectForbiddenFields(value: unknown, path: string, errors: string[]): void {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      rejectForbiddenFields(value[i], `${path}[${i}]`, errors);
    }
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (/\b(exec|generator|code|script|require|module|import|grant|override)\b/i.test(key)) {
        errors.push(`${path}.${key} is not allowed in corpus fixtures`);
      }
      rejectForbiddenFields(item, `${path}.${key}`, errors);
    }
  }
}

function boundedDepth(value: unknown, depth: number): boolean {
  if (depth > MAX_DEPTH) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.every((item) => boundedDepth(item, depth + 1));
  }
  if (isRecord(value)) {
    return Object.values(value).every((item) => boundedDepth(item, depth + 1));
  }
  return true;
}

/** Strict, bounded validation of a single corpus case. */
export function validateCorpusCase(input: unknown): CorpusCase | null {
  if (!isRecord(input) || !hasOnlyKeys(input, CASE_KEYS)) {
    return null;
  }
  if (!boundedString(input["id"])) {
    return null;
  }
  if (input["mode"] !== "attack" && input["mode"] !== "benign") {
    return null;
  }
  if (
    input["kind"] !== "static" &&
    input["kind"] !== "mutation" &&
    input["kind"] !== "adaptive-ready"
  ) {
    return null;
  }
  if (!isStringArray(input["attackClasses"]) || !isStringArray(input["invariants"])) {
    return null;
  }
  if (!Array.isArray(input["pages"])) {
    return null;
  }
  const pages: CorpusPage[] = [];
  for (const page of input["pages"] as readonly unknown[]) {
    if (!isRecord(page) || !hasOnlyKeys(page, PAGE_KEYS) || !boundedString(page["url"])) {
      return null;
    }
    if (page["origin"] !== undefined && !boundedString(page["origin"])) {
      return null;
    }
    pages.push({
      url: page["url"],
      ...(page["origin"] !== undefined ? { origin: page["origin"] } : {}),
    });
  }
  if (!boundedString(input["task"])) {
    return null;
  }
  const expected = input["expected"];
  if (
    !isRecord(expected) ||
    !hasOnlyKeys(expected, EXPECTED_KEYS) ||
    !boundedString(expected["outcome"])
  ) {
    return null;
  }
  if (!boundedDepth(input, 0)) {
    return null;
  }
  const errors: string[] = [];
  rejectForbiddenFields(input, "case", errors);
  if (errors.length > 0) {
    return null;
  }
  const built: Record<string, unknown> = {
    id: input["id"],
    mode: input["mode"],
    attackClasses: input["attackClasses"],
    invariants: input["invariants"],
    kind: input["kind"],
    pages,
    task: input["task"],
    expected: {
      outcome: expected["outcome"],
      ...(expected["reasons"] !== undefined ? { reasons: expected["reasons"] } : {}),
      ...(expected["findings"] !== undefined ? { findings: expected["findings"] } : {}),
      ...(expected["risk"] !== undefined ? { risk: expected["risk"] } : {}),
      ...(expected["control"] !== undefined ? { control: expected["control"] } : {}),
    },
  };
  if (input["surfaces"] !== undefined) {
    if (!isStringArray(input["surfaces"])) {
      return null;
    }
    built["surfaces"] = input["surfaces"];
  }
  if (input["initiator"] !== undefined) {
    if (!boundedString(input["initiator"])) {
      return null;
    }
    built["initiator"] = input["initiator"];
  }
  if (input["policy"] !== undefined) {
    if (!isRecord(input["policy"])) {
      return null;
    }
    built["policy"] = input["policy"];
  }
  if (input["steps"] !== undefined) {
    if (!Array.isArray(input["steps"])) {
      return null;
    }
    built["steps"] = input["steps"];
  }
  if (input["locale"] !== undefined) {
    if (!boundedString(input["locale"])) {
      return null;
    }
    built["locale"] = input["locale"];
  }
  if (input["tags"] !== undefined) {
    if (!isStringArray(input["tags"])) {
      return null;
    }
    built["tags"] = input["tags"];
  }
  return built as unknown as CorpusCase;
}

/** Deterministic corpus hash over the sorted, stable serialization of cases. */
export function corpusHash(cases: readonly CorpusCase[]): string {
  return hash(stableSerialize(cases));
}

export interface LoadedCorpus {
  readonly schemaVersion: string;
  readonly cases: readonly CorpusCase[];
  readonly hash: string;
}

/** Bounded loader: reads JSON, validates every case, and computes a hash. */
export function loadCorpusDocument(text: string): LoadedCorpus {
  if (Buffer.byteLength(text, "utf8") > MAX_FILE_BYTES) {
    throw new TypeError("corpus file exceeds the size limit");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError("corpus file is not valid JSON");
  }
  if (!isRecord(parsed) || parsed["schemaVersion"] !== CORPUS_SCHEMA_VERSION) {
    throw new TypeError("corpus document must declare the current schemaVersion");
  }
  const rawCases = parsed["cases"];
  if (!Array.isArray(rawCases) || rawCases.length > MAX_CASES) {
    throw new TypeError("corpus document must have a bounded cases array");
  }
  const cases: CorpusCase[] = [];
  for (const raw of rawCases) {
    const validated = validateCorpusCase(raw);
    if (validated === null) {
      throw new TypeError("corpus document contains an invalid case");
    }
    cases.push(validated);
  }
  return { schemaVersion: CORPUS_SCHEMA_VERSION, cases, hash: corpusHash(cases) };
}

/** Load a corpus document from a file path (bounded). */
export function loadCorpusFile(path: string): LoadedCorpus {
  return loadCorpusDocument(readFileSync(path, "utf8"));
}
