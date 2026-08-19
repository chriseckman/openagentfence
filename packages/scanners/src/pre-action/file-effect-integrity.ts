import {
  defineScanner,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { makeFinding } from "../helpers.js";

/**
 * Deterministic shape checks for browser effects whose bytes or destination
 * must be bound before execution. Capability and destination policy remain
 * core's final decision; this scanner makes malformed adapter input blocking
 * evidence rather than silently treating it as an ordinary click.
 */
export function createFileEffectIntegrityScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "file-effect-integrity",
    phases: ["PRE_ACTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      if (ctx.payload.kind !== "proposedAction") return emptyResult();
      const { action } = ctx.payload;
      const valid =
        (action.type === "SUBMIT" && validSubmit(action)) ||
        (action.type === "UPLOAD" && validUpload(action)) ||
        (action.type === "DOWNLOAD" && validDownload(action));
      if (action.type !== "SUBMIT" && action.type !== "UPLOAD" && action.type !== "DOWNLOAD") {
        return emptyResult();
      }
      if (valid) return emptyResult();
      const findings: Finding[] = [
        makeFinding(ctx.redactor, {
          id: `file-effect-integrity:${action.type.toLowerCase()}`,
          category: "malformed_file_effect",
          title: "Guarded browser effect lacks required bound metadata",
          description:
            "A form, upload, or download action must include the deterministic metadata required before execution.",
          sourceType: "file",
          ...(action.target?.origin !== undefined ? { origin: action.target.origin } : {}),
          evidence: action.type,
          recommendedAction: "block",
          severity: "high",
        }),
      ];
      return {
        scanner: "file-effect-integrity",
        kind: "deterministic",
        verdict: "block",
        severity: "high",
        findings,
      };
    },
  });
}

function validSubmit(action: { readonly destination?: string; readonly data?: unknown }): boolean {
  return (
    action.destination !== undefined &&
    isRecord(action.data) &&
    typeof action.data["method"] === "string"
  );
}

function validUpload(action: { readonly destination?: string; readonly data?: unknown }): boolean {
  if (!isRecord(action.data) || action.destination === undefined) return false;
  if (action.data["taskNecessary"] !== true || action.data["sensitivity"] === undefined)
    return false;
  const provenance = action.data["provenance"];
  const files = action.data["files"];
  return (
    isRecord(provenance) &&
    (provenance["trust"] === "application" || provenance["trust"] === "user") &&
    Array.isArray(files) &&
    files.length > 0 &&
    files.every(
      (file) =>
        isRecord(file) &&
        typeof file["name"] === "string" &&
        typeof file["bytes"] === "number" &&
        Number.isSafeInteger(file["bytes"]) &&
        file["bytes"] >= 0,
    )
  );
}

function validDownload(action: { readonly destination?: string }): boolean {
  return action.destination !== undefined;
}

function emptyResult(): ScanResult {
  return {
    scanner: "file-effect-integrity",
    kind: "deterministic",
    verdict: "allow",
    severity: "info",
    findings: [],
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
