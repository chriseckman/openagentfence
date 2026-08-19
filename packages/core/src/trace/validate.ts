import { AGGREGATE_VERDICTS } from "../contracts/verdict.js";
import { TRACE_EVENT_KINDS, TRACE_SCHEMA_VERSION } from "./events.js";

/**
 * Runtime validation for trace documents and events (ARCHITECTURE §14,
 * INV-17). Hand-rolled to keep `core` dependency-free, mirroring the
 * `validateFinding`/`validateScanResult` approach. It enforces the version
 * compatibility rule (same major, additive within a major), lifecycle
 * ordering (a `session_start` first, `session_end` last), well-formed
 * per-kind data, and reproducible redacted evidence-reference shapes.
 */
export interface TraceValidationResult {
  readonly ok: boolean;
  readonly errors: readonly string[];
}

const SEMVER = /^\d+\.\d+\.\d+$/;
const EVENT_KINDS = new Set<string>(TRACE_EVENT_KINDS);
const EVIDENCE_REFERENCE_KEYS = ["findingId", "category", "evidenceHash", "sourceType"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIn(value: unknown, allowed: readonly string[]): boolean {
  return typeof value === "string" && allowed.includes(value);
}

/** Numeric major of a semver string, or `null` when the string is not semver. */
export function schemaVersionMajor(version: string): number | null {
  if (!SEMVER.test(version)) {
    return null;
  }
  return Number(version.split(".")[0]);
}

/**
 * True when `version` shares the trace schema major and is at least as old as
 * the current schema (additive changes within a major remain replayable).
 */
export function isCompatibleSchemaVersion(
  version: string,
  expected: string = TRACE_SCHEMA_VERSION,
): boolean {
  const actual = schemaVersionMajor(version);
  const want = schemaVersionMajor(expected);
  return actual !== null && want !== null && actual === want;
}

function fail(errors: string[], message: string): void {
  errors.push(message);
}

function validateEvidenceReferences(value: unknown, errors: string[]): void {
  if (!Array.isArray(value)) {
    fail(errors, "evidence must be an array of references");
    return;
  }
  for (const item of value) {
    if (!isRecord(item)) {
      fail(errors, "each evidence reference must be an object");
      continue;
    }
    for (const key of EVIDENCE_REFERENCE_KEYS) {
      const field = item[key];
      if (typeof field !== "string" || field.length === 0) {
        fail(errors, `evidence reference.${key} must be a non-empty string`);
      }
    }
  }
}

/** Validate a single trace event's structural and per-kind data contract. */
export function validateTraceEvent(input: unknown): TraceValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { ok: false, errors: ["trace event must be an object"] };
  }
  const kind = input["kind"];
  if (typeof kind !== "string" || !EVENT_KINDS.has(kind)) {
    fail(errors, "kind must be a known trace event kind");
  }
  const timestamp = input["timestamp"];
  if (typeof timestamp !== "string" || timestamp.length === 0) {
    fail(errors, "timestamp must be a non-empty string");
  }
  const data = input["data"];
  if (!isRecord(data)) {
    fail(errors, "data must be an object");
    return { ok: false, errors };
  }

  switch (kind) {
    case "session_start": {
      if (typeof data["sessionId"] !== "string" || data["sessionId"].length === 0) {
        fail(errors, "session_start.sessionId must be a non-empty string");
      }
      if (typeof data["policyHash"] !== "string" || data["policyHash"].length === 0) {
        fail(errors, "session_start.policyHash must be a non-empty string");
      }
      const versions = data["versions"];
      if (!isRecord(versions) || typeof versions["schema"] !== "string") {
        fail(errors, "session_start.versions.schema must be a string");
      }
      break;
    }
    case "finding": {
      if (typeof data["id"] !== "string" || data["id"].length === 0) {
        fail(errors, "finding.id must be a non-empty string");
      }
      if (typeof data["evidenceHash"] !== "string" || data["evidenceHash"].length === 0) {
        fail(errors, "finding.evidenceHash must be a non-empty string");
      }
      break;
    }
    case "policy_decision": {
      const verdict = data["verdict"];
      if (!isIn(verdict, AGGREGATE_VERDICTS)) {
        fail(errors, "policy_decision.verdict must be a known aggregate verdict");
      }
      const reasons = data["reasons"];
      if (!Array.isArray(reasons) || !reasons.every((r) => typeof r === "string" && r.length > 0)) {
        fail(errors, "policy_decision.reasons must be an array of non-empty strings");
      }
      if (
        typeof verdict === "string" &&
        verdict !== "ALLOW" &&
        Array.isArray(reasons) &&
        reasons.length === 0
      ) {
        fail(errors, "a non-ALLOW policy_decision must carry at least one reason");
      }
      if (data["evidence"] !== undefined) {
        validateEvidenceReferences(data["evidence"], errors);
      }
      if (
        data["matchedRules"] !== undefined &&
        (!Array.isArray(data["matchedRules"]) ||
          !data["matchedRules"].every((rule) => typeof rule === "string" && rule.length > 0))
      ) {
        fail(errors, "policy_decision.matchedRules must be an array of non-empty strings");
      }
      if (
        data["appliedSuppressions"] !== undefined &&
        (!Array.isArray(data["appliedSuppressions"]) ||
          !data["appliedSuppressions"].every(
            (item) =>
              isRecord(item) &&
              typeof item["rule"] === "string" &&
              typeof item["scope"] === "string" &&
              typeof item["justification"] === "string",
          ))
      ) {
        fail(errors, "policy_decision.appliedSuppressions must contain trace-safe references");
      }
      break;
    }
    case "approval_request": {
      if (typeof data["id"] !== "string" || data["id"].length === 0) {
        fail(errors, "approval_request.id must be a non-empty string");
      }
      break;
    }
    case "approval_decision": {
      if (typeof data["id"] !== "string" || data["id"].length === 0) {
        fail(errors, "approval_decision.id must be a non-empty string");
      }
      if (typeof data["approved"] !== "boolean") {
        fail(errors, "approval_decision.approved must be a boolean");
      }
      break;
    }
    case "escape_hatch": {
      if (typeof data["reason"] !== "string" || data["reason"].length === 0) {
        fail(errors, "escape_hatch.reason must be a non-empty string");
      }
      break;
    }
    case "network_mutation": {
      if (typeof data["destination"] !== "string" || data["destination"].length === 0) {
        fail(errors, "network_mutation.destination must be a non-empty string");
      }
      if (typeof data["surface"] !== "string" || typeof data["initiator"] !== "string") {
        fail(errors, "network_mutation.surface and initiator must be strings");
      }
      break;
    }
    case "adapter_event": {
      if (
        (data["kind"] !== "navigation" &&
          data["kind"] !== "popup" &&
          data["kind"] !== "download") ||
        (data["url"] !== undefined && typeof data["url"] !== "string") ||
        (data["origin"] !== undefined && typeof data["origin"] !== "string") ||
        (data["pageId"] !== undefined && typeof data["pageId"] !== "string") ||
        (data["frameId"] !== undefined && typeof data["frameId"] !== "string") ||
        (data["revision"] !== undefined &&
          (!Number.isInteger(data["revision"]) || (data["revision"] as number) < 0)) ||
        (data["mainFrame"] !== undefined && typeof data["mainFrame"] !== "boolean")
      ) {
        fail(errors, "adapter_event must have a known kind and bounded string metadata");
      }
      break;
    }
    case "authorized_action": {
      if (typeof data["intentId"] !== "string" || data["intentId"].length === 0) {
        fail(errors, "authorized_action.intentId must be a non-empty string");
      }
      break;
    }
    case "action_revalidation": {
      if (typeof data["reason"] !== "string" || data["reason"].length === 0) {
        fail(errors, "action_revalidation.reason must be a non-empty string");
      }
      break;
    }
    case "risk_change": {
      if (typeof data["state"] !== "string" || data["state"].length === 0) {
        fail(errors, "risk_change.state must be a non-empty string");
      }
      break;
    }
    default:
      break;
  }

  return { ok: errors.length === 0, errors };
}

/** Validate a full trace document (version, event order, and per-event data). */
export function validateTraceDocument(input: unknown): TraceValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { ok: false, errors: ["trace document must be an object"] };
  }
  const schemaVersion = input["schemaVersion"];
  if (typeof schemaVersion !== "string" || !SEMVER.test(schemaVersion)) {
    fail(errors, "schemaVersion must be a semver string");
  } else if (!isCompatibleSchemaVersion(schemaVersion)) {
    fail(
      errors,
      `schemaVersion major ${schemaVersionMajor(schemaVersion)} is incompatible with ${TRACE_SCHEMA_VERSION}`,
    );
  }
  const events = input["events"];
  if (!Array.isArray(events)) {
    fail(errors, "events must be an array");
    return { ok: false, errors };
  }
  const eventList: readonly unknown[] = events;
  for (const event of eventList) {
    const result = validateTraceEvent(event);
    if (!result.ok) {
      errors.push(...result.errors);
    }
  }
  if (eventList.length > 0) {
    const first = eventList[0];
    if (isRecord(first) && first["kind"] !== "session_start") {
      fail(errors, "the first trace event must be session_start");
    }
    for (let i = 0; i < eventList.length - 1; i += 1) {
      const event = eventList[i];
      if (isRecord(event) && event["kind"] === "session_end") {
        fail(errors, "session_end must be the final trace event");
        break;
      }
    }
  }
  return { ok: errors.length === 0, errors };
}
