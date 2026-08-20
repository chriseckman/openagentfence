import type { BoundingBox, Finding, FindingSource, Severity } from "./finding.js";
import type { ScanResult } from "./scan-result.js";
import { provenanced, validateDataProvenance } from "./provenance.js";
import type { ScannerVerdict } from "./verdict.js";
import type { RedactedEvidence } from "../trace/redact.js";
import type { SanitizationSpan } from "../orchestrator/sanitize.js";

const FINDING_SOURCE_TYPES = [
  "dom",
  "url",
  "probe",
  "model",
  "tool",
  "memory",
  "file",
  "header",
] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const SCANNER_VERDICTS = ["allow", "warn", "sanitize", "approve", "block"] as const;
const KINDS = ["deterministic", "semantic"] as const;

const FINDING_KEYS = new Set([
  "id",
  "category",
  "title",
  "description",
  "source",
  "provenance",
  "evidence",
  "recommendedAction",
  "severity",
  "confidence",
]);

const SOURCE_KEYS = new Set(["type", "selector", "xpath", "origin", "frameOrigin", "boundingBox"]);
const BOX_KEYS = new Set(["x", "y", "width", "height"]);
const SCAN_RESULT_KEYS = new Set([
  "scanner",
  "kind",
  "verdict",
  "severity",
  "confidence",
  "findings",
  "sanitized",
  "sanitizations",
  "timedOut",
  "metadata",
]);

const SANITIZATION_SPAN_KEYS = new Set(["start", "end", "replacement", "provenance"]);

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

function isConfidence(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function validateBoundingBox(value: unknown): BoundingBox | null {
  if (!isRecord(value) || !hasOnlyKeys(value, BOX_KEYS)) {
    return null;
  }
  const { x, y, width, height } = value;
  if (
    typeof x !== "number" ||
    typeof y !== "number" ||
    typeof width !== "number" ||
    typeof height !== "number"
  ) {
    return null;
  }
  return { x, y, width, height };
}

function validateFindingSource(value: unknown): FindingSource | null {
  if (!isRecord(value) || !hasOnlyKeys(value, SOURCE_KEYS)) {
    return null;
  }
  if (!isIn(value["type"], FINDING_SOURCE_TYPES)) {
    return null;
  }
  if (value["selector"] !== undefined && typeof value["selector"] !== "string") {
    return null;
  }
  if (value["xpath"] !== undefined && typeof value["xpath"] !== "string") {
    return null;
  }
  if (value["origin"] !== undefined && typeof value["origin"] !== "string") {
    return null;
  }
  if (value["frameOrigin"] !== undefined && typeof value["frameOrigin"] !== "string") {
    return null;
  }
  const box = value["boundingBox"];
  const validatedBox = box === undefined ? null : validateBoundingBox(box);
  if (box !== undefined && validatedBox === null) {
    return null;
  }
  return {
    type: value["type"] as FindingSource["type"],
    ...(value["selector"] !== undefined ? { selector: value["selector"] as string } : {}),
    ...(value["xpath"] !== undefined ? { xpath: value["xpath"] as string } : {}),
    ...(value["origin"] !== undefined ? { origin: value["origin"] as string } : {}),
    ...(value["frameOrigin"] !== undefined ? { frameOrigin: value["frameOrigin"] as string } : {}),
    ...(validatedBox !== null ? { boundingBox: validatedBox } : {}),
  };
}

/**
 * Runtime schema validation for a `Finding` (strict unknown-field rejection).
 * The evidence brand is a construction-time invariant; this validator confirms
 * the structural contract and re-asserts it (TB9 plugin-scanner results).
 */
export function validateFinding(input: unknown): Finding | null {
  if (!isRecord(input) || !hasOnlyKeys(input, FINDING_KEYS)) {
    return null;
  }
  const id = input["id"];
  const category = input["category"];
  const title = input["title"];
  const description = input["description"];
  const evidence = input["evidence"];
  const recommendedAction = input["recommendedAction"];
  if (typeof id !== "string" || id.length === 0) {
    return null;
  }
  if (
    typeof category !== "string" ||
    typeof title !== "string" ||
    typeof description !== "string"
  ) {
    return null;
  }
  if (typeof evidence !== "string") {
    return null;
  }
  if (!isIn(recommendedAction, SCANNER_VERDICTS)) {
    return null;
  }
  const source = validateFindingSource(input["source"]);
  if (source === null) {
    return null;
  }
  const provenance = validateDataProvenance(input["provenance"]);
  if (provenance === null) {
    return null;
  }
  if (input["severity"] !== undefined && !isIn(input["severity"], SEVERITIES)) {
    return null;
  }
  if (input["confidence"] !== undefined && !isConfidence(input["confidence"])) {
    return null;
  }
  return {
    id,
    category,
    title,
    description,
    source,
    provenance,
    evidence: evidence as RedactedEvidence,
    recommendedAction: recommendedAction as ScannerVerdict,
    ...(input["severity"] !== undefined ? { severity: input["severity"] as Severity } : {}),
    ...(input["confidence"] !== undefined ? { confidence: input["confidence"] as number } : {}),
  };
}

/** Runtime schema validation for a `ScanResult` (strict unknown-field rejection). */
export function validateScanResult(input: unknown): ScanResult | null {
  if (!isRecord(input) || !hasOnlyKeys(input, SCAN_RESULT_KEYS)) {
    return null;
  }
  const scanner = input["scanner"];
  const kind = input["kind"];
  const verdict = input["verdict"];
  const severity = input["severity"];
  const findings = input["findings"];
  if (typeof scanner !== "string") {
    return null;
  }
  if (!isIn(kind, KINDS)) {
    return null;
  }
  if (!isIn(verdict, SCANNER_VERDICTS)) {
    return null;
  }
  if (!isIn(severity, SEVERITIES)) {
    return null;
  }
  if (!Array.isArray(findings)) {
    return null;
  }
  const validatedFindings: Finding[] = [];
  for (const item of findings) {
    const finding = validateFinding(item);
    if (finding === null) {
      return null;
    }
    validatedFindings.push(finding);
  }
  if (input["confidence"] !== undefined && !isConfidence(input["confidence"])) {
    return null;
  }
  const sanitized =
    input["sanitized"] === undefined ? undefined : validateProvenancedString(input["sanitized"]);
  if (input["sanitized"] !== undefined && sanitized === null) return null;
  const sanitizations = input["sanitizations"];
  if (sanitizations !== undefined) {
    if (!Array.isArray(sanitizations)) {
      return null;
    }
    for (const span of sanitizations) {
      if (validateSanitizationSpan(span) === null) {
        return null;
      }
    }
  }
  if (input["timedOut"] !== undefined && typeof input["timedOut"] !== "boolean") {
    return null;
  }
  if (input["metadata"] !== undefined && !isRecord(input["metadata"])) {
    return null;
  }
  return {
    scanner,
    kind: kind as ScanResult["kind"],
    verdict: verdict as ScannerVerdict,
    severity: severity as Severity,
    findings: validatedFindings,
    ...(input["confidence"] !== undefined ? { confidence: input["confidence"] as number } : {}),
    ...(sanitized !== undefined && sanitized !== null ? { sanitized } : {}),
    ...(sanitizations !== undefined
      ? { sanitizations: sanitizations.map((s) => s as SanitizationSpan) }
      : {}),
    ...(input["timedOut"] !== undefined ? { timedOut: input["timedOut"] as boolean } : {}),
    ...(input["metadata"] !== undefined
      ? { metadata: input["metadata"] as Readonly<Record<string, unknown>> }
      : {}),
  };
}

function validateSanitizationSpan(value: unknown): SanitizationSpan | null {
  if (!isRecord(value) || !hasOnlyKeys(value, SANITIZATION_SPAN_KEYS)) {
    return null;
  }
  const start = value["start"];
  const end = value["end"];
  const replacement = value["replacement"];
  const provenance = validateDataProvenance(value["provenance"]);
  if (typeof start !== "number" || !Number.isInteger(start) || start < 0) {
    return null;
  }
  if (typeof end !== "number" || !Number.isInteger(end) || end < start) {
    return null;
  }
  if (typeof replacement !== "string" || provenance === null) {
    return null;
  }
  return { start, end, replacement, provenance };
}

function validateProvenancedString(value: unknown) {
  if (!isRecord(value) || !hasOnlyKeys(value, new Set(["value", "provenance"]))) return null;
  if (typeof value["value"] !== "string") return null;
  const provenance = validateDataProvenance(value["provenance"]);
  return provenance === null ? null : provenanced(value["value"], provenance);
}
