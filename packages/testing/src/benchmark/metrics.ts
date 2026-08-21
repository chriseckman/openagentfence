/** Metric/outcome vocabulary for reproducible guarded-versus-unguarded reports. */
export const BENCHMARK_OUTCOME_KEYS = [
  "attackSuccess",
  "exfiltrationSuccess",
  "unauthorizedActionSuccess",
  "unauthorizedOriginTransition",
  "unauthorizedNetworkMutation",
  "secretResolutionBypass",
  "injectionDetection",
  "falsePositive",
  "legitimateCompletion",
  "restrictedRecovery",
  "actionIntentMismatchBlocked",
] as const;

export type BenchmarkOutcomeKey = (typeof BENCHMARK_OUTCOME_KEYS)[number];
export type BenchmarkOutcomeStatus = "success" | "failure" | "not_applicable" | "unsupported";

/**
 * Every case reports every outcome. `success` means the named event happened:
 * it is undesirable for attack/bypass/false-positive metrics and desirable for
 * detection/completion/recovery/mismatch-blocking metrics.
 */
export type BenchmarkOutcomes = Readonly<Record<BenchmarkOutcomeKey, BenchmarkOutcomeStatus>>;

export interface BenchmarkGuardMeasurement {
  readonly status: "invoked" | "not_invoked" | "not_applicable" | "unsupported";
  readonly calls: number;
  readonly reservedTokens: number;
  readonly budgetExhausted: "none" | "calls" | "tokens" | "calls_and_tokens";
}

export interface BenchmarkModelUsage {
  readonly status: "measured" | "unsupported";
  readonly inputTokens?: number;
  readonly outputTokens?: number;
  readonly costUsd?: number;
}

export interface BenchmarkNetworkMutationMeasurement {
  readonly initiator: NetworkInitiator;
  readonly surface: NetworkSurface;
  readonly enforcement: EnforcementLevel;
  readonly attempted: number;
  readonly succeeded: number;
}

export interface BenchmarkNetworkMutationMetric extends BenchmarkNetworkMutationMeasurement {
  readonly successRate: number | null;
}

export interface BenchmarkRateMetric {
  readonly numerator: number;
  readonly denominator: number;
  readonly unsupported: number;
  readonly notApplicable: number;
  readonly rate: number | null;
}

export interface BenchmarkLatencyMetric {
  readonly count: number;
  readonly medianMs: number | null;
  readonly p95Ms: number | null;
  readonly meanMs: number | null;
  readonly minMs: number | null;
  readonly maxMs: number | null;
}

export interface BenchmarkUsageMetric {
  readonly measuredCases: number;
  readonly unsupportedCases: number;
  readonly inputTokens: number | null;
  readonly outputTokens: number | null;
  readonly totalTokens: number | null;
  readonly costUsd: number | null;
}

export interface BenchmarkAggregateMetrics {
  readonly outcomes: Readonly<Record<BenchmarkOutcomeKey, BenchmarkRateMetric>>;
  readonly guardInvocation: BenchmarkRateMetric;
  readonly guardCallBudgetExhaustion: BenchmarkRateMetric;
  readonly guardTokenBudgetExhaustion: BenchmarkRateMetric;
  readonly totalGuardCalls: number;
  readonly guardCallsPerApplicableCase: number | null;
  readonly totalReservedGuardTokens: number;
  readonly latency: BenchmarkLatencyMetric;
  readonly usage: BenchmarkUsageMetric;
  readonly networkMutations: readonly BenchmarkNetworkMutationMetric[];
}

/** A single measured case, after the runner has attached identity/configuration. */
export interface BenchmarkCaseMeasurement {
  readonly caseId: string;
  readonly configuration: "unguarded" | "guarded";
  readonly outcomes: BenchmarkOutcomes;
  readonly guard: BenchmarkGuardMeasurement;
  readonly latencyMs: number;
  readonly usage: BenchmarkModelUsage;
  readonly networkMutations: readonly BenchmarkNetworkMutationMeasurement[];
}

export function aggregateBenchmarkMetrics(
  measurements: readonly BenchmarkCaseMeasurement[],
): BenchmarkAggregateMetrics {
  const outcomes = Object.fromEntries(
    BENCHMARK_OUTCOME_KEYS.map((key) => [
      key,
      rateMetric(measurements.map((measurement) => measurement.outcomes[key])),
    ]),
  ) as unknown as Readonly<Record<BenchmarkOutcomeKey, BenchmarkRateMetric>>;

  const guardStatuses: BenchmarkOutcomeStatus[] = measurements.map((measurement) => {
    switch (measurement.guard.status) {
      case "invoked":
        return "success";
      case "not_invoked":
        return "failure";
      case "not_applicable":
        return "not_applicable";
      case "unsupported":
        return "unsupported";
    }
  });
  const callExhaustionStatuses: BenchmarkOutcomeStatus[] = measurements.map((measurement) => {
    if (measurement.guard.status === "unsupported") return "unsupported";
    if (measurement.guard.status === "not_applicable") return "not_applicable";
    return ["calls", "calls_and_tokens"].includes(measurement.guard.budgetExhausted)
      ? "success"
      : "failure";
  });
  const tokenExhaustionStatuses: BenchmarkOutcomeStatus[] = measurements.map((measurement) => {
    if (measurement.guard.status === "unsupported") return "unsupported";
    if (measurement.guard.status === "not_applicable") return "not_applicable";
    return ["tokens", "calls_and_tokens"].includes(measurement.guard.budgetExhausted)
      ? "success"
      : "failure";
  });
  const latencies = measurements.map((measurement) => measurement.latencyMs).sort((a, b) => a - b);
  const measuredUsage = measurements.filter(
    (measurement) => measurement.usage.status === "measured",
  );
  const unsupportedUsage = measurements.length - measuredUsage.length;

  return Object.freeze({
    outcomes: Object.freeze(outcomes),
    guardInvocation: rateMetric(guardStatuses),
    guardCallBudgetExhaustion: rateMetric(callExhaustionStatuses),
    guardTokenBudgetExhaustion: rateMetric(tokenExhaustionStatuses),
    totalGuardCalls: measurements.reduce((total, item) => total + item.guard.calls, 0),
    guardCallsPerApplicableCase:
      guardStatuses.filter((status) => status !== "not_applicable" && status !== "unsupported")
        .length === 0
        ? null
        : round(
            measurements.reduce((total, item) => total + item.guard.calls, 0) /
              guardStatuses.filter(
                (status) => status !== "not_applicable" && status !== "unsupported",
              ).length,
          ),
    totalReservedGuardTokens: measurements.reduce(
      (total, item) => total + item.guard.reservedTokens,
      0,
    ),
    latency: Object.freeze({
      count: latencies.length,
      medianMs: percentile(latencies, 0.5),
      p95Ms: percentile(latencies, 0.95),
      meanMs:
        latencies.length === 0
          ? null
          : round(latencies.reduce((total, value) => total + value, 0) / latencies.length),
      minMs: latencies[0] ?? null,
      maxMs: latencies.at(-1) ?? null,
    }),
    usage: Object.freeze({
      measuredCases: measuredUsage.length,
      unsupportedCases: unsupportedUsage,
      inputTokens:
        unsupportedUsage === 0
          ? measuredUsage.reduce((total, item) => total + (item.usage.inputTokens ?? 0), 0)
          : null,
      outputTokens:
        unsupportedUsage === 0
          ? measuredUsage.reduce((total, item) => total + (item.usage.outputTokens ?? 0), 0)
          : null,
      totalTokens:
        unsupportedUsage === 0
          ? measuredUsage.reduce(
              (total, item) =>
                total + (item.usage.inputTokens ?? 0) + (item.usage.outputTokens ?? 0),
              0,
            )
          : null,
      costUsd:
        unsupportedUsage === 0 && measuredUsage.every((item) => item.usage.costUsd !== undefined)
          ? round(measuredUsage.reduce((total, item) => total + (item.usage.costUsd ?? 0), 0))
          : null,
    }),
    networkMutations: aggregateNetworkMutations(measurements),
  });
}

function aggregateNetworkMutations(
  measurements: readonly BenchmarkCaseMeasurement[],
): readonly BenchmarkNetworkMutationMetric[] {
  const groups = new Map<string, BenchmarkNetworkMutationMeasurement>();
  for (const measurement of measurements) {
    for (const mutation of measurement.networkMutations) {
      const key = `${mutation.initiator}:${mutation.surface}:${mutation.enforcement}`;
      const existing = groups.get(key);
      groups.set(key, {
        initiator: mutation.initiator,
        surface: mutation.surface,
        enforcement: mutation.enforcement,
        attempted: (existing?.attempted ?? 0) + mutation.attempted,
        succeeded: (existing?.succeeded ?? 0) + mutation.succeeded,
      });
    }
  }
  return Object.freeze(
    [...groups.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([, item]) =>
        Object.freeze({
          ...item,
          successRate:
            item.attempted === 0
              ? null
              : Math.round((item.succeeded / item.attempted) * 1_000_000) / 1_000_000,
        }),
      ),
  );
}

function rateMetric(statuses: readonly BenchmarkOutcomeStatus[]): BenchmarkRateMetric {
  const numerator = statuses.filter((status) => status === "success").length;
  const failures = statuses.filter((status) => status === "failure").length;
  const denominator = numerator + failures;
  return Object.freeze({
    numerator,
    denominator,
    unsupported: statuses.filter((status) => status === "unsupported").length,
    notApplicable: statuses.filter((status) => status === "not_applicable").length,
    rate: denominator === 0 ? null : round(numerator / denominator),
  });
}

function percentile(sorted: readonly number[], percentileValue: number): number | null {
  if (sorted.length === 0) return null;
  const index = Math.max(0, Math.ceil(sorted.length * percentileValue) - 1);
  return sorted[index] ?? null;
}

function round(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}
import type { EnforcementLevel, NetworkInitiator, NetworkSurface } from "@openagentfence/core";
