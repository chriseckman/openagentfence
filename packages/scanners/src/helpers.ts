import type {
  DataProvenance,
  Finding,
  FindingSource,
  ProbeResult,
  ScannerVerdict,
  SecurityContext,
  Severity,
} from "@openagentfence/core";
import type { Redactor } from "@openagentfence/core";

/** Extract the probe result from a PERCEPTION observation context, if any. */
export function getProbe(ctx: SecurityContext): ProbeResult | null {
  if (ctx.payload.kind === "observation") {
    return ctx.payload.observation.probe ?? null;
  }
  return null;
}

/** The observation's origin, or "" when the payload is not an observation. */
export function observationOrigin(ctx: SecurityContext): string {
  return ctx.payload.kind === "observation" ? ctx.payload.observation.origin : "";
}

export interface FindingSpec {
  readonly id: string;
  readonly category: string;
  readonly title: string;
  readonly description: string;
  readonly sourceType: FindingSource["type"];
  readonly selector?: string;
  readonly origin?: string;
  readonly frameOrigin?: string;
  readonly evidence: string;
  readonly recommendedAction: ScannerVerdict;
  readonly severity?: Severity;
  readonly confidence?: number;
}

/** Build a redacted finding with web provenance. Raw evidence text is redacted. */
export function makeFinding(redactor: Redactor, spec: FindingSpec): Finding {
  const source: FindingSource = {
    type: spec.sourceType,
    ...(spec.selector !== undefined ? { selector: spec.selector } : {}),
    ...(spec.origin !== undefined ? { origin: spec.origin } : {}),
    ...(spec.frameOrigin !== undefined ? { frameOrigin: spec.frameOrigin } : {}),
  };
  const provenance: DataProvenance = {
    trust: "web",
    ...(spec.origin !== undefined ? { origin: spec.origin } : {}),
    ...(spec.frameOrigin !== undefined ? { frameOrigin: spec.frameOrigin } : {}),
  };
  return {
    id: spec.id,
    category: spec.category,
    title: spec.title,
    description: spec.description,
    source,
    provenance,
    evidence: redactor.redact(spec.evidence),
    recommendedAction: spec.recommendedAction,
    ...(spec.severity !== undefined ? { severity: spec.severity } : {}),
    ...(spec.confidence !== undefined ? { confidence: spec.confidence } : {}),
  };
}

/** Bounded evidence excerpt (INV-16). */
export function excerpt(text: string, maxLength = 200): string {
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}…`;
}
