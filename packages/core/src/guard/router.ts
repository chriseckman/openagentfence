import type { Finding } from "../contracts/finding.js";
import type { DataProvenance } from "../contracts/provenance.js";
import type { ScanResult } from "../contracts/scan-result.js";
import type { RedactionRegistry } from "../trace/redact.js";
import {
  runGuardProvider,
  type GuardExecutionConstraints,
  type GuardProviderFailureKind,
} from "./execution.js";
import type { GuardModelProvider } from "./provider.js";
import type { GuardClassificationRequest } from "./request.js";
import type { GuardClassification } from "./classification.js";
import type { DetectorTier } from "./tier.js";

export interface SemanticTierSlot {
  readonly provider: GuardModelProvider;
  readonly constraints: GuardExecutionConstraints;
  readonly required?: boolean;
}

export type TierSkipReason =
  "not_configured" | "deterministic_critical" | "required_tier_failed" | "cancelled";

export interface DetectorTierMetric {
  readonly tier: DetectorTier;
  readonly status: "invoked" | "skipped";
  readonly outcome?: "success" | GuardProviderFailureKind;
  readonly skipReason?: TierSkipReason;
  readonly provider?: string;
}

export interface DetectorRouterInput {
  readonly runTier0: () => Promise<readonly ScanResult[]>;
  readonly request: GuardClassificationRequest;
  readonly provenance: DataProvenance;
  readonly redactor: RedactionRegistry;
  readonly tier1?: SemanticTierSlot;
  readonly tier2?: SemanticTierSlot;
}

export interface DetectorRouterResult {
  readonly results: readonly ScanResult[];
  readonly metrics: readonly DetectorTierMetric[];
  /** A deterministic critical result or required-tier failure forbids clean continuation. */
  readonly blockingFailure: boolean;
}

/**
 * Fixed provider-neutral detector order. Tier 0 always runs first. A critical
 * deterministic result skips both semantic tiers; Tier 1 and Tier 2 otherwise
 * run sequentially when configured. Semantic classifications and failures are
 * represented only as `kind: "semantic"` evidence (ADR-0003, INV-20).
 */
export async function runDetectorRouter(input: DetectorRouterInput): Promise<DetectorRouterResult> {
  const results: ScanResult[] = [];
  const metrics: DetectorTierMetric[] = [];
  let blockingFailure = false;

  try {
    const tier0 = await input.runTier0();
    if (tier0.some((result) => result.kind !== "deterministic")) {
      throw new TypeError("tier0 returned non-deterministic evidence");
    }
    results.push(...tier0);
    metrics.push({ tier: "tier0", status: "invoked", outcome: "success" });
  } catch {
    results.push(failureResult("tier0", "tier0", "exception", input, true));
    metrics.push({ tier: "tier0", status: "invoked", outcome: "exception" });
    blockingFailure = true;
  }

  if (blockingFailure || results.some(isCriticalDeterministic)) {
    blockingFailure = true;
    metrics.push(
      { tier: "tier1", status: "skipped", skipReason: "deterministic_critical" },
      { tier: "tier2", status: "skipped", skipReason: "deterministic_critical" },
    );
    return { results, metrics, blockingFailure };
  }

  const tier1 = await runSemanticTier("tier1", input.tier1, input);
  results.push(...tier1.results);
  metrics.push(tier1.metric);
  if (tier1.blockingFailure) blockingFailure = true;

  if (tier1.blockingFailure) {
    metrics.push({ tier: "tier2", status: "skipped", skipReason: "required_tier_failed" });
    return { results, metrics, blockingFailure };
  }
  if (input.tier1?.constraints.signal.aborted === true) {
    metrics.push({ tier: "tier2", status: "skipped", skipReason: "cancelled" });
    return { results, metrics, blockingFailure };
  }

  const tier2 = await runSemanticTier("tier2", input.tier2, input);
  results.push(...tier2.results);
  metrics.push(tier2.metric);
  if (tier2.blockingFailure) blockingFailure = true;
  return { results, metrics, blockingFailure };
}

async function runSemanticTier(
  tier: "tier1" | "tier2",
  slot: SemanticTierSlot | undefined,
  input: DetectorRouterInput,
): Promise<{
  readonly results: readonly ScanResult[];
  readonly metric: DetectorTierMetric;
  readonly blockingFailure: boolean;
}> {
  if (slot === undefined) {
    return {
      results: [],
      metric: { tier, status: "skipped", skipReason: "not_configured" },
      blockingFailure: false,
    };
  }
  const outcome = await runGuardProvider(slot.provider, input.request, slot.constraints);
  if (!outcome.ok) {
    return {
      results: [
        failureResult(tier, slot.provider.name, outcome.kind, input, slot.required === true),
      ],
      metric: {
        tier,
        status: "invoked",
        outcome: outcome.kind,
        provider: slot.provider.name,
      },
      blockingFailure: slot.required === true,
    };
  }
  return {
    results: [classificationResult(tier, slot.provider.name, outcome.value, input)],
    metric: { tier, status: "invoked", outcome: "success", provider: slot.provider.name },
    blockingFailure: false,
  };
}

function classificationResult(
  tier: "tier1" | "tier2",
  provider: string,
  classification: GuardClassification,
  input: DetectorRouterInput,
): ScanResult {
  const recommendedAction = classification.promptInjection
    ? classification.recommendedVerdict === "allow"
      ? "warn"
      : classification.recommendedVerdict
    : "allow";
  const finding: Finding = {
    id: `${tier}:${provider}:classification`,
    category: classification.promptInjection
      ? "semantic_prompt_injection"
      : "semantic_no_injection",
    title: "Semantic guard evidence",
    description: "A schema-validated semantic guard response was recorded as evidence only.",
    source: { type: "model" },
    provenance: input.provenance,
    evidence: input.redactor.redact(
      `provider=${provider}; categoryCount=${classification.categories.length}`,
    ),
    recommendedAction,
    confidence: classification.confidence,
  };
  return {
    scanner: `${tier}:${provider}`,
    kind: "semantic",
    verdict: recommendedAction,
    severity: classification.promptInjection ? "high" : "info",
    findings: [finding],
    metadata: { tier, provider, evidenceOnly: true },
  };
}

function failureResult(
  tier: DetectorTier,
  provider: string,
  kind: GuardProviderFailureKind,
  input: DetectorRouterInput,
  required: boolean,
): ScanResult {
  return {
    scanner: `${tier}:${provider}`,
    kind: tier === "tier0" ? "deterministic" : "semantic",
    verdict: required ? "block" : "warn",
    severity: required ? "critical" : "low",
    findings: [
      {
        id: `${tier}:${provider}:${kind}`,
        category: "scanner_unavailable",
        title: "Detector tier unavailable",
        description: `Detector ${tier} failed (${kind}) and did not produce trusted authority.`,
        source: { type: "tool" },
        provenance: input.provenance,
        evidence: input.redactor.redact(`detector ${tier} unavailable (${kind})`),
        recommendedAction: required ? "block" : "warn",
      },
    ],
    metadata: { tier, provider, failureKind: kind, required, evidenceOnly: tier !== "tier0" },
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
