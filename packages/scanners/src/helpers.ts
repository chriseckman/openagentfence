import type {
  DataProvenance,
  Finding,
  FindingSource,
  ProbeResult,
  ScannerVerdict,
  SecurityContext,
  Severity,
} from "@openagentfence/core";

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
  /** Original observation/action source; scanner output cannot invent trust. */
  readonly provenance?: DataProvenance;
  readonly evidence: string;
  readonly recommendedAction: ScannerVerdict;
  readonly severity?: Severity;
  readonly confidence?: number;
}

/** Build a redacted finding without losing the security-context source. */
export function makeFinding(ctx: SecurityContext, spec: FindingSpec): Finding {
  // Selectors and origins are browser-derived and may contain a registered
  // sensitive value. Redact every string copied into public finding and
  // provenance metadata, not only the evidence excerpt (INV-05/13).
  const selector = spec.selector === undefined ? undefined : ctx.redactor.redact(spec.selector);
  const origin = spec.origin === undefined ? undefined : ctx.redactor.redact(spec.origin);
  const frameOrigin =
    spec.frameOrigin === undefined ? undefined : ctx.redactor.redact(spec.frameOrigin);
  const source: FindingSource = {
    type: spec.sourceType,
    ...(selector !== undefined ? { selector } : {}),
    ...(origin !== undefined ? { origin } : {}),
    ...(frameOrigin !== undefined ? { frameOrigin } : {}),
  };
  const provenance: DataProvenance = {
    ...(spec.provenance ?? ctx.provenance),
    ...(origin !== undefined ? { origin } : {}),
    ...(frameOrigin !== undefined ? { frameOrigin } : {}),
    ...(selector !== undefined ? { elementId: selector } : {}),
  };
  return {
    id: ctx.redactor.redact(spec.id),
    category: ctx.redactor.redact(spec.category),
    title: ctx.redactor.redact(spec.title),
    description: ctx.redactor.redact(spec.description),
    source,
    provenance,
    evidence: ctx.redactor.redact(spec.evidence),
    recommendedAction: spec.recommendedAction,
    ...(spec.severity !== undefined ? { severity: spec.severity } : {}),
    ...(spec.confidence !== undefined ? { confidence: spec.confidence } : {}),
  };
}

/** Bounded evidence excerpt (INV-16). */
export function excerpt(text: string, maxLength = 200): string {
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}…`;
}
