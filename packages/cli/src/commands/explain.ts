import { validateTraceDocument, type TraceDocument, type TraceEvent } from "@openagentfence/core";
import {
  CLI_EXIT,
  isBoundedFileSize,
  isBoundedPath,
  MAX_CLI_INPUT_BYTES,
  nodeFileSystem,
  type CliFileSystem,
  type CliIo,
} from "./common.js";

const SAFE_DATA_KEYS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  session_start: ["sessionId", "policyHash", "versions"],
  observation: ["provenance"],
  taint_activation: ["source", "provenance"],
  finding: ["id", "category", "sourceType", "evidenceHash", "provenance"],
  risk_change: ["state", "score", "previousState", "signal"],
  proposed_action: ["type", "instructionProvenance", "dataProvenance"],
  canonical_action: ["type", "instructionProvenance", "dataProvenance"],
  policy_decision: [
    "verdict",
    "reasons",
    "evidence",
    "matchedRules",
    "appliedSuppressions",
    "policyHash",
  ],
  session_end: ["risk", "score"],
});

export interface ExplainDependencies {
  readonly files?: CliFileSystem;
}

export async function runExplainCommand(
  args: readonly string[],
  io: CliIo,
  dependencies: ExplainDependencies = {},
): Promise<number> {
  const parsed = parseExplainArgs(args);
  if (parsed === null) {
    io.stderr("usage: openagentfence explain <redacted-trace.json> [--json]\n");
    return CLI_EXIT.usage;
  }
  const files = dependencies.files ?? nodeFileSystem;
  try {
    const metadata = await files.stat(parsed.path);
    if (!isBoundedFileSize(metadata.size)) throw new TypeError("trace exceeds bounds");
    const source = await files.readFile(parsed.path);
    if (Buffer.byteLength(source, "utf8") > MAX_CLI_INPUT_BYTES)
      throw new TypeError("trace exceeds bounds");
    const document: unknown = JSON.parse(source) as unknown;
    const validation = validateTraceDocument(document);
    if (!validation.ok || !isPresentationSafeTrace(document)) throw new TypeError("trace invalid");
    const projection = projectTrace(document);
    io.stdout(parsed.json ? `${JSON.stringify(projection)}\n` : renderProjection(projection));
    return CLI_EXIT.success;
  } catch {
    io.stderr("trace is invalid, unsafe, or unavailable\n");
    return CLI_EXIT.failure;
  }
}

interface ParsedExplainArgs {
  readonly path: string;
  readonly json: boolean;
}

interface ExplainProjection {
  readonly schemaVersion: string;
  readonly decisions: readonly {
    readonly timestamp: string;
    readonly kind: string;
    readonly verdict?: string;
    readonly reasons?: readonly string[];
    readonly evidence?: readonly {
      readonly category: string;
      readonly evidenceHash: string;
      readonly sourceType: string;
    }[];
  }[];
}

function parseExplainArgs(args: readonly string[]): ParsedExplainArgs | null {
  let path: string | undefined;
  let json = false;
  for (const argument of args) {
    if (argument === "--json" && !json) {
      json = true;
      continue;
    }
    if (path === undefined && isBoundedPath(argument)) {
      path = argument;
      continue;
    }
    return null;
  }
  return path === undefined ? null : Object.freeze({ path, json });
}

function isPresentationSafeTrace(input: unknown): input is TraceDocument {
  if (
    !isPlainRecord(input) ||
    Object.keys(input).some((key) => key !== "schemaVersion" && key !== "events") ||
    !Array.isArray(input["events"])
  )
    return false;
  for (const event of input["events"]) {
    if (
      !isPlainRecord(event) ||
      Object.keys(event).some((key) => key !== "kind" && key !== "timestamp" && key !== "data") ||
      typeof event["kind"] !== "string" ||
      !isSafeTimestamp(event["timestamp"]) ||
      !isPlainRecord(event["data"])
    )
      return false;
    const allowed = SAFE_DATA_KEYS[event["kind"]];
    if (
      allowed === undefined ||
      Object.keys(event["data"]).some((key) => !allowed.includes(key)) ||
      !hasSafeEvidence(event["data"])
    )
      return false;
  }
  return true;
}

function hasSafeEvidence(data: Record<string, unknown>): boolean {
  const evidence = data["evidence"];
  if (evidence === undefined) return true;
  return (
    Array.isArray(evidence) &&
    evidence.every(
      (item) =>
        isPlainRecord(item) &&
        Object.keys(item).every((key) =>
          ["findingId", "category", "evidenceHash", "sourceType"].includes(key),
        ) &&
        typeof item["findingId"] === "string" &&
        /^[a-z][a-z0-9_.-]{0,127}$/u.test(String(item["category"])) &&
        /^[a-f0-9]{64}$/u.test(String(item["evidenceHash"])) &&
        /^[a-z][a-z0-9_.-]{0,127}$/u.test(String(item["sourceType"])),
    )
  );
}

function isSafeTimestamp(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value);
}

function projectTrace(document: TraceDocument): ExplainProjection {
  const decisions = document.events
    .filter(
      (event) =>
        event.kind === "finding" ||
        event.kind === "policy_decision" ||
        event.kind === "risk_change",
    )
    .map((event) => projectEvent(event));
  return Object.freeze({
    schemaVersion: document.schemaVersion,
    decisions: Object.freeze(decisions),
  });
}

function projectEvent(event: TraceEvent): ExplainProjection["decisions"][number] {
  const data = event.data;
  if (event.kind === "policy_decision") {
    return Object.freeze({
      timestamp: event.timestamp,
      kind: event.kind,
      ...(typeof data["verdict"] === "string" ? { verdict: data["verdict"] } : {}),
      ...(Array.isArray(data["reasons"]) &&
      data["reasons"].every((item) => typeof item === "string")
        ? { reasons: Object.freeze([...data["reasons"]] as string[]) }
        : {}),
      ...(Array.isArray(data["evidence"])
        ? {
            evidence: Object.freeze(
              data["evidence"].flatMap((item) =>
                isPlainRecord(item) &&
                typeof item["category"] === "string" &&
                typeof item["evidenceHash"] === "string" &&
                typeof item["sourceType"] === "string"
                  ? [
                      Object.freeze({
                        category: item["category"],
                        evidenceHash: item["evidenceHash"],
                        sourceType: item["sourceType"],
                      }),
                    ]
                  : [],
              ),
            ),
          }
        : {}),
    });
  }
  return Object.freeze({ timestamp: event.timestamp, kind: event.kind });
}

function renderProjection(projection: ExplainProjection): string {
  const lines = [`trace schema: ${projection.schemaVersion}`];
  for (const event of projection.decisions) {
    const details = [event.verdict, event.reasons?.join(",")].filter(
      (item): item is string => item !== undefined && item.length > 0,
    );
    lines.push(
      `${event.timestamp} ${event.kind}${details.length === 0 ? "" : ` ${details.join(" ")}`}`,
    );
  }
  return `${lines.join("\n")}\n`;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}
