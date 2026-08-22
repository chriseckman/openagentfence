import {
  defineScanner,
  type DataProvenance,
  type GuardClassification,
  type GuardProviderFailureKind,
  type GuardProviderOutcome,
  type RedactedEvidence,
  type ScanResult,
  type SecurityContext,
  type SessionGuardClassifier,
  type SessionGuardScannerFactory,
} from "@openagentfence/core";
import { decodeIterative } from "../../normalize/decoders.js";
import { DEFAULT_DECODE_LIMITS } from "../../normalize/limits.js";
import { scanInjection } from "../../perception/injection-heuristics/rules.js";
import { classifyObservation, isHiddenClass } from "../../perception/visibility/classify.js";

export const BYOK_INJECTION_LIMITS = Object.freeze({
  maxExcerpts: 8,
  maxExcerptBytes: 512,
  maxTotalExcerptBytes: 4_096,
  maxTaskBytes: 512,
  maxInputBytes: 5_120,
  maxOutputBytes: 4_096,
  maxTokens: 512,
});

export interface ByokInjectionScannerOptions {
  readonly localeHints?: readonly string[];
  /** Fail closed for later high-impact actions when this check is unavailable. */
  readonly required?: boolean;
}

interface Candidate {
  readonly key: string;
  readonly text: string;
  readonly selector?: string;
  readonly frameOrigin?: string;
}

interface SelectedExcerpts {
  readonly excerpts: readonly RedactedEvidence[];
  readonly totalBytes: number;
  readonly firstCandidate?: Candidate;
}

/**
 * Create one explicitly opt-in Tier 2 scanner per session. The supplied core
 * callback owns provider access, budgets, cancellation, and response schema
 * validation; this package never imports a provider implementation.
 */
export function createByokInjectionScannerFactory(
  options: ByokInjectionScannerOptions = {},
): SessionGuardScannerFactory {
  const localeHints = validateLocaleHints(options.localeHints ?? []);
  return (classify: SessionGuardClassifier) =>
    defineScanner({
      id: "byok-injection",
      phases: ["PERCEPTION", "MODEL_OUTPUT"],
      kind: "semantic",
      tier: "tier2",
      priority: 100,
      required: options.required === true,
      async scan(ctx: SecurityContext): Promise<ScanResult> {
        const selected = selectByokInjectionExcerpts(ctx);
        if (selected.excerpts.length === 0) {
          return emptyResult();
        }
        const taskSummary = ctx.redactor.redact(
          truncateUtf8(
            ctx.redactor.redact(ctx.taskContract.task),
            BYOK_INJECTION_LIMITS.maxTaskBytes,
          ),
        );
        let outcome: GuardProviderOutcome;
        try {
          outcome = await classify(
            {
              role: "text_injection",
              excerpts: selected.excerpts,
              taskSummary,
              localeHints,
              budget: { maxTokens: BYOK_INJECTION_LIMITS.maxTokens },
            },
            {
              signal: ctx.signal,
              deadline: ctx.deadline,
              maxInputBytes: BYOK_INJECTION_LIMITS.maxInputBytes,
              maxOutputBytes: BYOK_INJECTION_LIMITS.maxOutputBytes,
              maxTokens: BYOK_INJECTION_LIMITS.maxTokens,
            },
          );
        } catch {
          outcome = { ok: false, kind: "exception" };
        }
        return outcome.ok
          ? classificationResult(ctx, outcome.value, selected)
          : unavailableResult(ctx, outcome.kind, selected);
      },
    });
}

/** Select stable, structural regions without ever serializing a whole page. */
export function selectByokInjectionExcerpts(ctx: SecurityContext): SelectedExcerpts {
  const candidates = candidatesFor(ctx).sort((a, b) => a.key.localeCompare(b.key));
  const excerpts: RedactedEvidence[] = [];
  const seen = new Set<string>();
  let totalBytes = 0;
  let firstCandidate: Candidate | undefined;

  for (const candidate of candidates) {
    if (excerpts.length >= BYOK_INJECTION_LIMITS.maxExcerpts) break;
    const redacted = ctx.redactor.redact(candidate.text.trim());
    if (redacted.length === 0) continue;
    const bounded = truncateUtf8(redacted, BYOK_INJECTION_LIMITS.maxExcerptBytes);
    if (seen.has(bounded)) continue;
    const bytes = Buffer.byteLength(bounded, "utf8");
    if (totalBytes + bytes > BYOK_INJECTION_LIMITS.maxTotalExcerptBytes) break;
    seen.add(bounded);
    excerpts.push(ctx.redactor.redact(bounded));
    totalBytes += bytes;
    firstCandidate ??= candidate;
  }
  return {
    excerpts: Object.freeze(excerpts),
    totalBytes,
    ...(firstCandidate !== undefined ? { firstCandidate } : {}),
  };
}

function candidatesFor(ctx: SecurityContext): Candidate[] {
  if (ctx.payload.kind === "modelOutput") {
    const content = ctx.payload.output.content;
    const matches = scanInjection(content);
    return (matches.length > 0 ? matches.map((match) => match.evidence) : [content]).map(
      (text, index) => ({ key: `model:${index.toString().padStart(4, "0")}`, text }),
    );
  }
  if (ctx.payload.kind !== "observation" || ctx.payload.observation.probe === undefined) {
    return [];
  }
  const probe = ctx.payload.observation.probe;
  const candidates: Candidate[] = [];
  for (const classified of classifyObservation(probe).nodes) {
    const node = classified.node;
    const sources = [
      node.text,
      node.ariaLabel ?? "",
      node.ariaDescription ?? "",
      node.pseudoBefore ?? "",
      node.pseudoAfter ?? "",
      ...Object.values(node.attributes),
    ];
    const matched = sources.flatMap((text) => scanInjection(text).map((match) => match.evidence));
    const decoded = decodeIterative(
      node.text,
      DEFAULT_DECODE_LIMITS.maxDecodeDepth,
      DEFAULT_DECODE_LIMITS.deadlineMs,
    );
    if (decoded.status === "decoded") {
      matched.push(...scanInjection(decoded.text).map((match) => match.evidence));
    }
    const structural = isHiddenClass(classified.visibility)
      ? sources.filter((text) => text.trim().length > 0)
      : [];
    for (const [index, text] of [...matched, ...structural].entries()) {
      candidates.push({
        key: `node:${node.selector}:${index.toString().padStart(4, "0")}`,
        text,
        selector: node.selector,
        frameOrigin: node.frameOrigin,
      });
    }
  }
  const metadata = [
    ...probe.comments.map((text, index) => ({ key: `comment:${index}`, text })),
    ...Object.entries(probe.metadata.meta).map(([key, text]) => ({ key: `meta:${key}`, text })),
    ...probe.metadata.jsonLd.map((text, index) => ({ key: `jsonld:${index}`, text })),
    ...probe.metadata.noscript.map((text, index) => ({ key: `noscript:${index}`, text })),
  ];
  candidates.push(...metadata);
  return candidates;
}

function classificationResult(
  ctx: SecurityContext,
  classification: GuardClassification,
  selected: SelectedExcerpts,
): ScanResult {
  const recommendation = classification.promptInjection
    ? classification.recommendedVerdict === "allow"
      ? "warn"
      : classification.recommendedVerdict
    : "allow";
  const candidate = selected.firstCandidate;
  const provenance: DataProvenance = {
    ...ctx.provenance,
    ...(candidate?.selector !== undefined ? { elementId: candidate.selector } : {}),
    ...(candidate?.frameOrigin !== undefined ? { frameOrigin: candidate.frameOrigin } : {}),
  };
  return {
    scanner: "byok-injection",
    kind: "semantic",
    verdict: recommendation,
    severity: classification.promptInjection ? "high" : "info",
    confidence: classification.confidence,
    findings: [
      {
        id: "byok-injection:classification",
        category: classification.promptInjection
          ? "semantic_prompt_injection"
          : "semantic_no_injection",
        title: "Semantic injection evidence",
        description: "A bounded BYOK classifier response was recorded as evidence only.",
        source: {
          type: "model",
          ...(candidate?.selector !== undefined ? { selector: candidate.selector } : {}),
          ...(candidate?.frameOrigin !== undefined ? { frameOrigin: candidate.frameOrigin } : {}),
        },
        provenance,
        evidence: ctx.redactor.redact(
          `promptInjection=${classification.promptInjection}; categoryCount=${classification.categories.length}`,
        ),
        recommendedAction: recommendation,
        severity: classification.promptInjection ? "high" : "info",
        confidence: classification.confidence,
      },
    ],
    metadata: {
      tier: "tier2",
      evidenceOnly: true,
      excerptCount: selected.excerpts.length,
      excerptBytes: selected.totalBytes,
      categoryCount: classification.categories.length,
    },
  };
}

function unavailableResult(
  ctx: SecurityContext,
  kind: GuardProviderFailureKind,
  selected: SelectedExcerpts,
): ScanResult {
  return {
    scanner: "byok-injection",
    kind: "semantic",
    verdict: "warn",
    severity: "low",
    findings: [
      {
        id: `byok-injection:${kind}`,
        category: "scanner_unavailable",
        title: "BYOK injection scanner unavailable",
        description: `The optional Tier 2 check failed (${kind}) and did not produce authority.`,
        source: { type: "model" },
        provenance: ctx.provenance,
        evidence: ctx.redactor.redact(`Tier 2 unavailable (${kind})`),
        recommendedAction: "warn",
        severity: "low",
      },
    ],
    metadata: {
      tier: "tier2",
      evidenceOnly: true,
      failureKind: kind,
      excerptCount: selected.excerpts.length,
      excerptBytes: selected.totalBytes,
    },
  };
}

function emptyResult(): ScanResult {
  return {
    scanner: "byok-injection",
    kind: "semantic",
    verdict: "allow",
    severity: "info",
    findings: [],
    metadata: { tier: "tier2", evidenceOnly: true, excerptCount: 0, excerptBytes: 0 },
  };
}

function validateLocaleHints(hints: readonly string[]): readonly string[] {
  if (hints.length > 8 || hints.some((hint) => !/^[A-Za-z0-9-]{1,35}$/.test(hint))) {
    throw new TypeError("localeHints must contain at most eight bounded language tags");
  }
  return Object.freeze([...hints]);
}

function truncateUtf8(value: string, maxBytes: number): string {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) return value;
  let output = "";
  for (const symbol of value) {
    if (Buffer.byteLength(output + symbol, "utf8") > maxBytes) break;
    output += symbol;
  }
  return output;
}
