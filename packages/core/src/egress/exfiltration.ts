import type { CanonicalAction } from "../action/canonical-action.js";
import { originOf, sameOrigin } from "../action/url.js";
import { REASON_CODES, type ReasonCode } from "../policy/reasons.js";

export const EXFILTRATION_ACTION_TYPES = [
  "NAVIGATE",
  "SUBMIT",
  "UPLOAD",
  "MESSAGE",
  "PASTE",
] as const;

export interface CrossOriginExfiltrationFacts {
  readonly currentOrigin?: string;
  readonly sessionTainted: boolean;
  readonly valueMatched: boolean;
  readonly handlePresent: boolean;
  readonly exactSinkBound: boolean;
  readonly destinationInTaskScope: boolean;
}

export interface CrossOriginExfiltrationEvaluation {
  readonly blocked: boolean;
  readonly reasons: readonly ReasonCode[];
}

/** Fixed layer-3 v0.1 source-to-sink rule. It never consumes semantic evidence. */
export function evaluateCrossOriginExfiltration(
  action: CanonicalAction,
  facts: CrossOriginExfiltrationFacts,
): CrossOriginExfiltrationEvaluation {
  if (!(EXFILTRATION_ACTION_TYPES as readonly string[]).includes(action.type)) return clean();
  const datumTrust = action.data?.provenance.trust;
  const taintedDatum = datumTrust === "web" || datumTrust === "tool" || datumTrust === "memory";
  const sensitive =
    facts.sessionTainted ||
    taintedDatum ||
    action.instructionProvenance.trust === "web" ||
    facts.valueMatched ||
    facts.handlePresent;
  if (!sensitive) return clean();

  const destination = action.destination ?? action.target?.origin;
  const destinationOrigin = destination === undefined ? null : originOf(destination);
  const sourceOrigin =
    facts.currentOrigin ??
    action.target?.origin ??
    action.data?.provenance.origin ??
    action.instructionProvenance.origin;
  const crossOrigin =
    destinationOrigin === null ||
    sourceOrigin === undefined ||
    !sameOrigin(destinationOrigin, sourceOrigin);
  if (!crossOrigin || facts.exactSinkBound) return clean();

  const reasons: ReasonCode[] = [REASON_CODES.untrusted_cross_origin_egress];
  if (facts.valueMatched || facts.handlePresent || facts.sessionTainted || taintedDatum) {
    reasons.push(REASON_CODES.secret_sink_not_allowed);
  }
  if (!facts.destinationInTaskScope) reasons.push(REASON_CODES.destination_not_allowed);
  if (action.type === "NAVIGATE" && action.instructionProvenance.trust === "web") {
    reasons.push(REASON_CODES.navigation_instruction_originated_from_untrusted_dom);
  }
  return { blocked: true, reasons };
}

function clean(): CrossOriginExfiltrationEvaluation {
  return { blocked: false, reasons: [] };
}
