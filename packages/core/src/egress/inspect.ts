import { originOf } from "../action/url.js";
import { validateDataProvenance } from "../contracts/provenance.js";
import { REASON_CODES, type ReasonCode } from "../policy/reasons.js";
import { EGRESS_SINKS, type EgressPayload } from "./payload.js";
import { MAX_EGRESS_VALUE_BYTES } from "./match.js";
import type { SourceValueEvidence } from "../provenance/value-registry.js";

export interface EgressMatchResult {
  readonly fingerprints: readonly string[];
  readonly sources?: readonly SourceValueEvidence[];
  readonly incomplete: boolean;
}

export interface EgressInspection {
  readonly verdict: "allow" | "block";
  readonly reasons: readonly ReasonCode[];
  readonly inspectedBytes: number;
  readonly matchCount: number;
  /** Fingerprint + provenance only; never the matched raw value. */
  readonly matchedSources?: readonly SourceValueEvidence[];
}

/** Provider/adapter-neutral interception interface for future proxy integrations. */
export interface EgressInspector {
  inspect(payload: EgressPayload, signal?: AbortSignal): EgressInspection;
}

export interface EgressInspectorOptions {
  readonly match: (value: string, signal?: AbortSignal) => EgressMatchResult;
  readonly isDestinationAllowed: (
    fingerprint: string,
    destinationOrigin: string,
    sink: EgressPayload["sink"],
    fieldType?: string,
  ) => boolean;
  readonly maxValueBytes?: number;
}

export function createEgressInspector(options: EgressInspectorOptions): EgressInspector {
  const maxValueBytes = options.maxValueBytes ?? MAX_EGRESS_VALUE_BYTES;
  if (!Number.isInteger(maxValueBytes) || maxValueBytes < 1) {
    throw new TypeError("maxValueBytes must be a positive integer");
  }
  return {
    inspect(payload: EgressPayload, signal?: AbortSignal): EgressInspection {
      const invalid = invalidPayload(payload, maxValueBytes) || signal?.aborted === true;
      if (invalid) return incomplete(payload.byteLength);
      const matched = options.match(payload.value, signal);
      if (matched.incomplete || isAborted(signal)) return incomplete(payload.byteLength);
      const destinationOrigin = originOf(payload.destination);
      if (destinationOrigin === null && matched.fingerprints.length > 0) {
        return blocked(payload.byteLength, matched.fingerprints.length, matched.sources);
      }
      if (
        destinationOrigin !== null &&
        matched.fingerprints.some(
          (fingerprint) =>
            !options.isDestinationAllowed(
              fingerprint,
              destinationOrigin,
              payload.sink,
              payload.fieldType,
            ),
        )
      ) {
        return blocked(payload.byteLength, matched.fingerprints.length, matched.sources);
      }
      return {
        verdict: "allow",
        reasons: [],
        inspectedBytes: payload.byteLength,
        matchCount: matched.fingerprints.length,
        ...(matched.sources !== undefined && matched.sources.length > 0
          ? { matchedSources: matched.sources }
          : {}),
      };
    },
  };
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}

function invalidPayload(payload: EgressPayload, maxValueBytes: number): boolean {
  return (
    typeof payload.destination !== "string" ||
    payload.destination.length === 0 ||
    payload.destination.length > 4096 ||
    !(EGRESS_SINKS as readonly string[]).includes(payload.sink) ||
    typeof payload.value !== "string" ||
    !Number.isInteger(payload.byteLength) ||
    payload.byteLength < 0 ||
    payload.byteLength > maxValueBytes ||
    !payload.complete ||
    validateDataProvenance(payload.provenance) === null
  );
}

function incomplete(bytes: number): EgressInspection {
  return {
    verdict: "block",
    reasons: [REASON_CODES.egress_inspection_incomplete],
    inspectedBytes: Math.max(0, bytes),
    matchCount: 0,
  };
}

function blocked(
  bytes: number,
  matchCount: number,
  matchedSources?: readonly SourceValueEvidence[],
): EgressInspection {
  return {
    verdict: "block",
    reasons: [REASON_CODES.sensitive_value_in_egress],
    inspectedBytes: bytes,
    matchCount,
    ...(matchedSources !== undefined && matchedSources.length > 0 ? { matchedSources } : {}),
  };
}
