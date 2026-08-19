import { validateProbeResult } from "../probe/validate.js";
import type { BrowserAdapter } from "./browser-adapter.js";
import type { PageObservation } from "./observation.js";

/**
 * Framework-neutral adapter conformance suite (OAF-CORE-011). Adapter packages
 * run this against their own adapter to prove the observation, capability, and
 * escape-hatch contracts before claiming support. It contains no framework
 * dependency and is safe to run against any `BrowserAdapter`.
 */

export interface ConformanceCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly detail?: string;
}

export interface AdapterConformanceReport {
  readonly ok: boolean;
  readonly checks: readonly ConformanceCheck[];
}

const CAPABILITY_FLAGS = [
  "route",
  "navigationEvents",
  "downloadEvents",
  "popupEvents",
  "screenshot",
  "ariaSnapshot",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Structural checks for a `PageObservation`; returns a list of errors. */
export function validatePageObservation(input: unknown): string[] {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return ["observation must be an object"];
  }
  if (typeof input["url"] !== "string" || typeof input["origin"] !== "string") {
    errors.push("observation must have string url and origin");
  }
  const frames = input["frames"];
  if (!Array.isArray(frames)) {
    errors.push("observation.frames must be an array");
  } else {
    for (const frame of frames) {
      if (
        !isRecord(frame) ||
        typeof frame["url"] !== "string" ||
        typeof frame["origin"] !== "string"
      ) {
        errors.push("each frame must have string url and origin");
        break;
      }
    }
  }
  const provenance = input["provenance"];
  if (!isRecord(provenance) || provenance["trust"] !== "web") {
    errors.push("observation provenance must be web trust");
  }
  if (input["probe"] !== undefined && validateProbeResult(input["probe"]) === null) {
    errors.push("observation.probe failed runtime validation");
  }
  for (const key of ["pageId", "contextId"] as const) {
    if (input[key] !== undefined && typeof input[key] !== "string") {
      errors.push(`observation.${key} must be a string when present`);
    }
  }
  if (
    input["revision"] !== undefined &&
    (!Number.isInteger(input["revision"]) || (input["revision"] as number) < 0)
  ) {
    errors.push("observation.revision must be a non-negative integer when present");
  }
  return errors;
}

/**
 * Run the adapter conformance contract against an adapter. Every check is
 * observational: an adapter cannot advertise a capability that its returned
 * observation or conformance behavior does not support.
 */
export async function runAdapterConformance(
  adapter: BrowserAdapter,
): Promise<AdapterConformanceReport> {
  const checks: ConformanceCheck[] = [];

  const caps = adapter.capabilities;
  for (const flag of CAPABILITY_FLAGS) {
    checks.push({
      name: `capabilities.${flag}`,
      ok: isRecord(caps) && typeof caps[flag] === "boolean",
    });
  }

  try {
    const observation = await adapter.observe();
    const errors = validatePageObservation(observation);
    checks.push({
      name: "observe returns a valid PageObservation",
      ok: errors.length === 0,
      detail: errors.join("; "),
    });
  } catch (err) {
    checks.push({
      name: "observe returns a valid PageObservation",
      ok: false,
      detail: String(err),
    });
  }

  try {
    const raw = adapter.rawPage("adapter-conformance");
    checks.push({
      name: "rawPage returns the raw framework handle",
      ok: raw !== undefined && raw !== null,
    });
  } catch (err) {
    checks.push({
      name: "rawPage returns the raw framework handle",
      ok: false,
      detail: String(err),
    });
  }

  try {
    const dispose = adapter.subscribe("adapter-conformance", {
      onNavigation: () => {},
      onPopup: () => false,
      onDownload: () => {},
    });
    dispose();
    checks.push({ name: "subscribe accepts an event sink", ok: true });
  } catch (err) {
    checks.push({ name: "subscribe accepts an event sink", ok: false, detail: String(err) });
  }

  return { ok: checks.every((c) => c.ok), checks };
}

/** Re-export the observation type for adapter-package convenience. */
export type { PageObservation };
