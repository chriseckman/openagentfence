import type { SecurityPhase } from "../contracts/phase.js";
import type { SecurityContext } from "../scanner/context.js";
import type { SecurityScanner } from "../scanner/scanner.js";
import type { ScanResult } from "../contracts/scan-result.js";
import type { Finding } from "../contracts/finding.js";
import type { SanitizationSpan } from "./sanitize.js";
import type { ProvenancedDatum } from "../contracts/provenance.js";
import { ScannerRegistry } from "./registry.js";
import { runWithDeadline, type DeadlineFailureKind } from "./timeouts.js";
import { DEFAULT_RESOURCE_LIMITS, type ResourceLimits } from "./limits.js";
import { isHighImpact } from "../action/classify.js";
import { validateScanResult } from "../contracts/validation.js";
import { defaultTierForKind, type DetectorTier } from "../guard/tier.js";

/** The distinct failure classes an orchestrator can observe (INV-09). */
export type ScanFailureKind = DeadlineFailureKind | "malformed" | "oversized" | "budget_exhausted";

export interface ScannerFailure {
  readonly scanner: string;
  readonly kind: ScanFailureKind;
}

export interface RunPhaseResult {
  readonly results: readonly ScanResult[];
  readonly failures: readonly ScannerFailure[];
  readonly sanitizedTexts: readonly ProvenancedDatum<string>[];
  readonly sanitizationSpans: readonly SanitizationSpan[];
  readonly oversized: boolean;
  readonly tierMetrics: readonly PhaseTierMetric[];
  readonly requiredGuardChecked: boolean;
  readonly requiredGuardFailure: boolean;
}

/** Bounded routing evidence; never contains scanner input or output. */
export interface PhaseTierMetric {
  readonly tier: DetectorTier;
  readonly status: "invoked" | "skipped";
  readonly scannerCount: number;
  readonly skipReason?: "not_configured" | "deterministic_critical" | "cancelled";
}

interface RunOutcome {
  readonly result: ScanResult | null;
  readonly failure: ScannerFailure | null;
}

/**
 * Run all scanners for a phase under one absolute phase deadline
 * (ARCHITECTURE §6): deterministic scanners run concurrently, then semantic
 * scanners under a concurrency limit. Per-scanner deadlines are bounded by the
 * remaining phase time. Timeout, cancellation, exception, and malformed results
 * are distinguished and never masquerade as `allow`.
 */
export async function runPhase(
  registry: ScannerRegistry,
  phase: SecurityPhase,
  ctx: SecurityContext,
  limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
): Promise<RunPhaseResult> {
  const scanners = registry.list(phase);
  const detectorTier = (scanner: SecurityScanner): DetectorTier =>
    scanner.tier ?? defaultTierForKind(scanner.kind);
  const deterministic = scanners.filter((s) => detectorTier(s) === "tier0");
  const tier1 = scanners.filter((s) => detectorTier(s) === "tier1");
  const tier2 = scanners.filter((s) => detectorTier(s) === "tier2");

  const phaseDeadline = Date.now() + limits.phaseDeadlineMs;
  const oversized = isOversizedObservation(ctx, limits);

  const deterministicOutcomes = await Promise.all(
    deterministic.map((s) => runOne(s, phase, ctx, phaseDeadline)),
  );
  const deterministicCritical = deterministicOutcomes.some(
    (outcome) => outcome.result !== null && isCriticalDeterministic(outcome.result),
  );
  const tierMetrics: PhaseTierMetric[] = [
    { tier: "tier0", status: "invoked", scannerCount: deterministic.length },
  ];
  const tier1Outcomes = deterministicCritical
    ? []
    : await runConcurrent(tier1, limits.scannerConcurrency, (s) =>
        runOne(s, phase, ctx, phaseDeadline),
      );
  tierMetrics.push(
    deterministicCritical
      ? {
          tier: "tier1",
          status: "skipped",
          scannerCount: tier1.length,
          skipReason: "deterministic_critical",
        }
      : tier1.length === 0
        ? { tier: "tier1", status: "skipped", scannerCount: 0, skipReason: "not_configured" }
        : { tier: "tier1", status: "invoked", scannerCount: tier1.length },
  );
  const cancelled = ctx.signal.aborted || Date.now() >= phaseDeadline;
  const tier2Outcomes =
    deterministicCritical || cancelled
      ? []
      : await runConcurrent(tier2, limits.scannerConcurrency, (s) =>
          runOne(s, phase, ctx, phaseDeadline),
        );
  tierMetrics.push(
    deterministicCritical
      ? {
          tier: "tier2",
          status: "skipped",
          scannerCount: tier2.length,
          skipReason: "deterministic_critical",
        }
      : cancelled
        ? { tier: "tier2", status: "skipped", scannerCount: tier2.length, skipReason: "cancelled" }
        : tier2.length === 0
          ? { tier: "tier2", status: "skipped", scannerCount: 0, skipReason: "not_configured" }
          : { tier: "tier2", status: "invoked", scannerCount: tier2.length },
  );

  const results: ScanResult[] = [];
  const failures: ScannerFailure[] = [];
  const sanitizedTexts: ProvenancedDatum<string>[] = [];
  const sanitizationSpans: SanitizationSpan[] = [];
  const semanticById = new Map([...tier1, ...tier2].map((scanner) => [scanner.id, scanner]));

  if (oversized) {
    failures.push({ scanner: "observation", kind: "oversized" });
    results.push({
      scanner: "observation",
      kind: "deterministic",
      verdict: "warn",
      severity: "medium",
      findings: [unavailableFinding("observation", ctx, "oversized", "warn")],
      metadata: { failureKind: "oversized" },
    });
  }

  for (const outcome of [...deterministicOutcomes, ...tier1Outcomes, ...tier2Outcomes]) {
    if (outcome.result !== null) {
      results.push(outcome.result);
      if (outcome.result.sanitized !== undefined) {
        sanitizedTexts.push(outcome.result.sanitized);
      }
      if (outcome.result.sanitizations !== undefined) {
        sanitizationSpans.push(...outcome.result.sanitizations);
      }
    }
    if (outcome.failure !== null) {
      failures.push(outcome.failure);
    }
  }

  const semanticOutcomes = [...tier1Outcomes, ...tier2Outcomes];
  const requiredScanners = [...tier1, ...tier2].filter((scanner) => scanner.required === true);
  const requiredGuardChecked = requiredScanners.length > 0 && !deterministicCritical && !cancelled;
  const requiredGuardFailure =
    requiredGuardChecked &&
    semanticOutcomes.some((outcome) => {
      const scannerId = outcome.failure?.scanner ?? outcome.result?.scanner;
      const scanner = scannerId === undefined ? undefined : semanticById.get(scannerId);
      return (
        scanner?.required === true &&
        (outcome.failure !== null || outcome.result?.metadata?.["failureKind"] !== undefined)
      );
    });

  return {
    results,
    failures,
    sanitizedTexts,
    sanitizationSpans,
    oversized,
    tierMetrics,
    requiredGuardChecked,
    requiredGuardFailure,
  };
}

function isCriticalDeterministic(result: ScanResult): boolean {
  return (
    result.kind === "deterministic" &&
    (result.verdict === "block" ||
      result.findings.some(
        (finding) =>
          finding.recommendedAction === "block" &&
          (finding.severity === "critical" || result.severity === "critical"),
      ))
  );
}

async function runOne(
  scanner: SecurityScanner,
  phase: SecurityPhase,
  ctx: SecurityContext,
  phaseDeadline: number,
): Promise<RunOutcome> {
  const remaining = phaseDeadline - Date.now();
  if (remaining <= 0) {
    return { result: null, failure: { scanner: scanner.id, kind: "timeout" } };
  }
  const timeoutMs = Math.min(scanner.timeoutMs ?? Number.POSITIVE_INFINITY, remaining);

  const outcome = await runWithDeadline(
    (signal) => scanner.scan({ ...ctx, signal, deadline: phaseDeadline }),
    timeoutMs,
    ctx.signal,
  );

  if (!outcome.ok) {
    return {
      result: failureResult(scanner, phase, ctx, outcome.kind),
      failure: { scanner: scanner.id, kind: outcome.kind },
    };
  }

  const validated = validateScanResult(outcome.value);
  if (validated === null) {
    return {
      result: failureResult(scanner, phase, ctx, "malformed"),
      failure: { scanner: scanner.id, kind: "malformed" },
    };
  }
  return { result: validated, failure: null };
}

async function runConcurrent<T>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T) => Promise<RunOutcome>,
): Promise<RunOutcome[]> {
  const limit = Math.max(1, concurrency);
  const results: RunOutcome[] = new Array<RunOutcome>(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const index = next;
      next += 1;
      const item = items[index];
      if (item !== undefined) {
        results[index] = await fn(item);
      }
    }
  }
  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(limit, items.length); i += 1) {
    workers.push(worker());
  }
  await Promise.all(workers);
  return results;
}

function isOversizedObservation(ctx: SecurityContext, limits: ResourceLimits): boolean {
  if (ctx.payload.kind !== "observation") {
    return false;
  }
  const probe = ctx.payload.observation.probe;
  if (probe === undefined) {
    return false;
  }
  return probe.truncated || probe.nodes.length > limits.maxNodes;
}

function failureResult(
  scanner: SecurityScanner,
  phase: SecurityPhase,
  ctx: SecurityContext,
  kind: ScanFailureKind,
): ScanResult {
  const failClosed =
    scanner.kind === "deterministic" &&
    (phase === "EGRESS" ||
      phase === "PERSISTENCE" ||
      (phase === "PRE_ACTION" &&
        ctx.payload.kind === "proposedAction" &&
        isHighImpact(ctx.payload.action)));

  return {
    scanner: scanner.id,
    kind: scanner.kind,
    verdict: failClosed ? "block" : "warn",
    severity: failClosed ? "critical" : "low",
    findings: [unavailableFinding(scanner.id, ctx, kind, failClosed ? "block" : "warn")],
    timedOut: kind === "timeout",
    metadata: { failureKind: kind },
  };
}

function unavailableFinding(
  scannerId: string,
  ctx: SecurityContext,
  kind: ScanFailureKind,
  recommendedAction: "warn" | "block",
): Finding {
  return {
    id: `${scannerId}:${kind}`,
    category: "scanner_unavailable",
    title: "Scanner unavailable",
    description: `Scanner ${scannerId} failed (${kind}) and did not complete its required check.`,
    source: { type: "tool" },
    provenance: ctx.provenance,
    evidence: ctx.redactor.redact(`scanner ${scannerId} failed (${kind})`),
    recommendedAction,
  };
}
