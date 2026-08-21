import {
  ENFORCEMENT_LEVELS,
  hash,
  NETWORK_INITIATORS,
  NETWORK_SURFACES,
  stableSerialize,
} from "@openagentfence/core";
import {
  aggregateBenchmarkMetrics,
  BENCHMARK_OUTCOME_KEYS,
  type BenchmarkAggregateMetrics,
  type BenchmarkRateMetric,
} from "./metrics.js";
import {
  BENCHMARK_SCHEMA_VERSION,
  type BenchmarkPinnedMetadata,
  type BenchmarkReport,
} from "./runner.js";

/** Stable JSON representation of a validated in-memory report. */
export function benchmarkReportJson(report: BenchmarkReport): string {
  if (!validateBenchmarkReport(report)) throw new TypeError("benchmark report is invalid");
  return `${JSON.stringify(report, null, 2)}\n`;
}

/** Parse a report through the closed runtime boundary and verify its integrity hash. */
export function parseBenchmarkReport(text: string): BenchmarkReport {
  if (Buffer.byteLength(text, "utf8") > 16 * 1024 * 1024) {
    throw new TypeError("benchmark report exceeds the size limit");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError("benchmark report is not valid JSON");
  }
  if (!validateBenchmarkReport(parsed)) throw new TypeError("benchmark report is invalid");
  return parsed;
}

/** Closed, bounded report validation used before publication or comparison. */
export function validateBenchmarkReport(value: unknown): value is BenchmarkReport {
  const report = record(value, [
    "schemaVersion",
    "runId",
    "generatedAt",
    "profile",
    "seed",
    "metadata",
    "caseIds",
    "applicability",
    "measurements",
    "metrics",
    "comparison",
    "reportHash",
  ]);
  if (
    report === null ||
    report["schemaVersion"] !== BENCHMARK_SCHEMA_VERSION ||
    !safeText(report["runId"], 256) ||
    !isoDate(report["generatedAt"]) ||
    !uint(report["seed"], 0xffff_ffff) ||
    !hexHash(report["reportHash"])
  )
    return false;

  const profile = record(report["profile"], ["name", "maxCases", "caseTimeoutMs", "runTimeoutMs"]);
  const metadata = validateMetadata(report["metadata"]);
  const caseIds = stringArray(report["caseIds"], 4_096);
  const applicability = report["applicability"];
  const measurements = report["measurements"];
  const metrics = record(report["metrics"], ["unguarded", "guarded"]);
  const comparison = record(report["comparison"], [
    "addedMedianLatencyMs",
    "tokenDelta",
    "costDeltaUsd",
  ]);
  if (
    profile === null ||
    !["pr", "nightly", "full", "custom"].includes(profile["name"] as string) ||
    !uint(profile["maxCases"], 4_096, 1) ||
    !uint(profile["caseTimeoutMs"], 60_000, 1) ||
    !uint(profile["runTimeoutMs"], 3_600_000, 1) ||
    profile["runTimeoutMs"] < profile["caseTimeoutMs"] ||
    metadata === null ||
    caseIds === null ||
    caseIds.length === 0 ||
    new Set(caseIds).size !== caseIds.length ||
    [...caseIds].sort().join("\0") !== caseIds.join("\0") ||
    !Array.isArray(applicability) ||
    applicability.length !== caseIds.length ||
    applicability.some((item) => !validateApplicability(item, caseIds)) ||
    new Set(applicability.map((item) => (item as { caseId?: unknown }).caseId)).size !==
      caseIds.length ||
    !Array.isArray(measurements) ||
    measurements.length !== caseIds.length * 2 ||
    measurements.some((item) => !validateMeasurement(item, caseIds, applicability)) ||
    metrics === null ||
    !validateAggregate(metrics["unguarded"]) ||
    !validateAggregate(metrics["guarded"]) ||
    comparison === null ||
    !nullableFinite(comparison["addedMedianLatencyMs"]) ||
    !nullableFinite(comparison["tokenDelta"]) ||
    !nullableFinite(comparison["costDeltaUsd"])
  )
    return false;

  for (const caseId of caseIds) {
    const pair = measurements.filter(
      (item) =>
        typeof item === "object" &&
        item !== null &&
        (item as { caseId?: unknown }).caseId === caseId,
    );
    if (
      pair.length !== 2 ||
      !pair.some((item) => (item as { configuration?: unknown }).configuration === "guarded") ||
      !pair.some((item) => (item as { configuration?: unknown }).configuration === "unguarded")
    )
      return false;
  }
  const typed = measurements as BenchmarkReport["measurements"];
  const raw = aggregateBenchmarkMetrics(typed.filter((item) => item.configuration === "unguarded"));
  const guarded = aggregateBenchmarkMetrics(
    typed.filter((item) => item.configuration === "guarded"),
  );
  if (
    stableSerialize(metrics["unguarded"]) !== stableSerialize(raw) ||
    stableSerialize(metrics["guarded"]) !== stableSerialize(guarded) ||
    stableSerialize(comparison) !== stableSerialize(recomputeComparison(typed, caseIds))
  )
    return false;
  const withoutHash = { ...report };
  delete withoutHash["reportHash"];
  return hash(stableSerialize(withoutHash)) === report["reportHash"];
}

/** Markdown summary with definitions and explicit unsupported counts. */
export function benchmarkReportMarkdown(report: BenchmarkReport): string {
  if (!validateBenchmarkReport(report)) throw new TypeError("benchmark report is invalid");
  const rows = BENCHMARK_OUTCOME_KEYS.map(
    (key) =>
      `| ${key} | ${formatRate(report.metrics.unguarded.outcomes[key])} | ${formatRate(report.metrics.guarded.outcomes[key])} |`,
  );
  return [
    `# OpenAgentFence benchmark: ${report.runId}`,
    "",
    "> Measured results only. `n/a` means zero denominator; unsupported observations are explicit and never counted as clean.",
    "",
    `- Report schema: \`${report.schemaVersion}\``,
    `- Report hash: \`${report.reportHash}\``,
    `- Corpus: \`${report.metadata.corpusSchemaVersion}\` / \`${report.metadata.corpusHash}\``,
    `- Policy hash: \`${report.metadata.policyHash}\``,
    `- Framework: ${pin(report.metadata.framework)}`,
    `- Browser: ${pin(report.metadata.browser)}`,
    `- Primary agent: ${pin(report.metadata.primaryAgent)}`,
    `- Guard providers: ${report.metadata.guardProviders.map(pin).join(", ")}`,
    `- Runner: \`${report.metadata.runnerVersion}\`; seed: \`${report.seed}\`; profile: \`${report.profile.name}\``,
    "",
    "| Metric (numerator event) | Unguarded | Guarded |",
    "| --- | ---: | ---: |",
    ...rows,
    `| guardInvocation | ${formatRate(report.metrics.unguarded.guardInvocation)} | ${formatRate(report.metrics.guarded.guardInvocation)} |`,
    `| guardCallBudgetExhaustion | ${formatRate(report.metrics.unguarded.guardCallBudgetExhaustion)} | ${formatRate(report.metrics.guarded.guardCallBudgetExhaustion)} |`,
    `| guardTokenBudgetExhaustion | ${formatRate(report.metrics.unguarded.guardTokenBudgetExhaustion)} | ${formatRate(report.metrics.guarded.guardTokenBudgetExhaustion)} |`,
    "",
    "## Timing and usage",
    "",
    `- Median latency: unguarded ${formatNumber(report.metrics.unguarded.latency.medianMs)} ms; guarded ${formatNumber(report.metrics.guarded.latency.medianMs)} ms; paired added median ${formatNumber(report.comparison.addedMedianLatencyMs)} ms.`,
    `- Total tokens: unguarded ${formatNumber(report.metrics.unguarded.usage.totalTokens)}; guarded ${formatNumber(report.metrics.guarded.usage.totalTokens)}; delta ${formatNumber(report.comparison.tokenDelta)}.`,
    `- Cost USD: unguarded ${formatNumber(report.metrics.unguarded.usage.costUsd)}; guarded ${formatNumber(report.metrics.guarded.usage.costUsd)}; delta ${formatNumber(report.comparison.costDeltaUsd)}.`,
    `- Unsupported usage observations: unguarded ${report.metrics.unguarded.usage.unsupportedCases}; guarded ${report.metrics.guarded.usage.unsupportedCases}.`,
    "",
  ].join("\n");
}

function validateMetadata(value: unknown): BenchmarkPinnedMetadata | null {
  const metadata = record(value, [
    "corpusHash",
    "corpusSchemaVersion",
    "policyHash",
    "framework",
    "browser",
    "primaryAgent",
    "guardProviders",
    "runnerVersion",
  ]);
  if (
    metadata === null ||
    !hexHash(metadata["corpusHash"]) ||
    !hexHash(metadata["policyHash"]) ||
    !safeText(metadata["corpusSchemaVersion"], 64) ||
    !safeText(metadata["runnerVersion"], 256)
  )
    return null;
  for (const key of ["framework", "browser", "primaryAgent"] as const) {
    const model = key === "primaryAgent";
    const component = record(
      metadata[key],
      model ? ["name", "version", "model"] : ["name", "version"],
    );
    if (
      component === null ||
      !safeText(component["name"], 256) ||
      !exactVersion(component["version"]) ||
      (model && !safeText(component["model"], 256))
    )
      return null;
  }
  if (
    !Array.isArray(metadata["guardProviders"]) ||
    metadata["guardProviders"].length === 0 ||
    metadata["guardProviders"].length > 8
  )
    return null;
  for (const provider of metadata["guardProviders"]) {
    const component = record(provider, ["name", "version", "model"]);
    if (
      component === null ||
      !safeText(component["name"], 256) ||
      !exactVersion(component["version"]) ||
      !safeText(component["model"], 256)
    )
      return null;
  }
  return value as BenchmarkPinnedMetadata;
}

function validateMeasurement(
  value: unknown,
  caseIds: readonly string[],
  applicability: readonly unknown[],
): boolean {
  const item = record(value, [
    "caseId",
    "configuration",
    "outcomes",
    "guard",
    "latencyMs",
    "usage",
    "networkMutations",
  ]);
  const outcomes = item === null ? null : record(item["outcomes"], BENCHMARK_OUTCOME_KEYS);
  const guard =
    item === null
      ? null
      : record(item["guard"], ["status", "calls", "reservedTokens", "budgetExhausted"]);
  const usage =
    item === null
      ? null
      : record(item["usage"], ["status", "inputTokens", "outputTokens", "costUsd"]);
  if (item === null || typeof item["caseId"] !== "string") return false;
  const app = applicability.find(
    (entry) =>
      typeof entry === "object" &&
      entry !== null &&
      (entry as { caseId?: unknown }).caseId === item["caseId"],
  ) as { outcomes?: unknown; guardOpportunity?: unknown } | undefined;
  const applicableOutcomes = app?.outcomes;
  const outcomeApplicabilityValid =
    Array.isArray(applicableOutcomes) &&
    outcomes !== null &&
    BENCHMARK_OUTCOME_KEYS.every(
      (key) =>
        (applicableOutcomes.includes(key) && outcomes[key] !== "not_applicable") ||
        (!applicableOutcomes.includes(key) && outcomes[key] === "not_applicable"),
    );
  return (
    caseIds.includes(item["caseId"]) &&
    ["unguarded", "guarded"].includes(item["configuration"] as string) &&
    outcomes !== null &&
    BENCHMARK_OUTCOME_KEYS.every((key) =>
      ["success", "failure", "not_applicable", "unsupported"].includes(outcomes[key] as string),
    ) &&
    outcomeApplicabilityValid &&
    guard !== null &&
    ["invoked", "not_invoked", "not_applicable", "unsupported"].includes(
      guard["status"] as string,
    ) &&
    uint(guard["calls"], 1_000_000) &&
    uint(guard["reservedTokens"], 1_000_000_000) &&
    ["none", "calls", "tokens", "calls_and_tokens"].includes(guard["budgetExhausted"] as string) &&
    ((guard["status"] === "invoked" && guard["calls"] >= 1) ||
      (guard["status"] !== "invoked" && guard["calls"] === 0)) &&
    ((item["configuration"] === "unguarded" && guard["status"] === "not_applicable") ||
      (item["configuration"] === "guarded" &&
        ((app?.guardOpportunity === true && guard["status"] !== "not_applicable") ||
          (app?.guardOpportunity === false && guard["status"] === "not_applicable")))) &&
    finiteBetween(item["latencyMs"], 0, 60_000) &&
    Array.isArray(item["networkMutations"]) &&
    item["networkMutations"].length <= 128 &&
    item["networkMutations"].every((entry) => validateNetworkMutation(entry)) &&
    usage !== null &&
    ((usage["status"] === "measured" &&
      uint(usage["inputTokens"], 1_000_000_000) &&
      uint(usage["outputTokens"], 1_000_000_000) &&
      (usage["costUsd"] === undefined || finiteBetween(usage["costUsd"], 0, 1_000_000))) ||
      (usage["status"] === "unsupported" &&
        usage["inputTokens"] === undefined &&
        usage["outputTokens"] === undefined &&
        usage["costUsd"] === undefined))
  );
}

function validateApplicability(value: unknown, caseIds: readonly string[]): boolean {
  const item = record(value, ["caseId", "outcomes", "guardOpportunity"]);
  const outcomes =
    item === null ? null : stringArray(item["outcomes"], BENCHMARK_OUTCOME_KEYS.length);
  return (
    item !== null &&
    typeof item["caseId"] === "string" &&
    caseIds.includes(item["caseId"]) &&
    outcomes !== null &&
    new Set(outcomes).size === outcomes.length &&
    outcomes.every((key) =>
      BENCHMARK_OUTCOME_KEYS.includes(key as (typeof BENCHMARK_OUTCOME_KEYS)[number]),
    ) &&
    typeof item["guardOpportunity"] === "boolean"
  );
}

function validateAggregate(value: unknown): value is BenchmarkAggregateMetrics {
  const aggregate = record(value, [
    "outcomes",
    "guardInvocation",
    "guardCallBudgetExhaustion",
    "guardTokenBudgetExhaustion",
    "totalGuardCalls",
    "guardCallsPerApplicableCase",
    "totalReservedGuardTokens",
    "latency",
    "usage",
    "networkMutations",
  ]);
  if (aggregate === null) return false;
  const outcomes = record(aggregate["outcomes"], BENCHMARK_OUTCOME_KEYS);
  const latency = record(aggregate["latency"], [
    "count",
    "medianMs",
    "p95Ms",
    "meanMs",
    "minMs",
    "maxMs",
  ]);
  const usage = record(aggregate["usage"], [
    "measuredCases",
    "unsupportedCases",
    "inputTokens",
    "outputTokens",
    "totalTokens",
    "costUsd",
  ]);
  return (
    outcomes !== null &&
    BENCHMARK_OUTCOME_KEYS.every((key) => validateRate(outcomes[key])) &&
    validateRate(aggregate["guardInvocation"]) &&
    validateRate(aggregate["guardCallBudgetExhaustion"]) &&
    validateRate(aggregate["guardTokenBudgetExhaustion"]) &&
    uint(aggregate["totalGuardCalls"], 1_000_000_000) &&
    nullableFinite(aggregate["guardCallsPerApplicableCase"]) &&
    uint(aggregate["totalReservedGuardTokens"], 1_000_000_000) &&
    latency !== null &&
    uint(latency["count"], 4_096) &&
    ["medianMs", "p95Ms", "meanMs", "minMs", "maxMs"].every((key) =>
      nullableFinite(latency[key]),
    ) &&
    usage !== null &&
    uint(usage["measuredCases"], 4_096) &&
    uint(usage["unsupportedCases"], 4_096) &&
    nullableUint(usage["inputTokens"]) &&
    nullableUint(usage["outputTokens"]) &&
    nullableUint(usage["totalTokens"]) &&
    nullableFinite(usage["costUsd"]) &&
    Array.isArray(aggregate["networkMutations"]) &&
    aggregate["networkMutations"].length <= 128 &&
    aggregate["networkMutations"].every((item) => validateNetworkMutation(item, true))
  );
}

function validateNetworkMutation(value: unknown, aggregate = false): boolean {
  const keys = [
    "initiator",
    "surface",
    "enforcement",
    "attempted",
    "succeeded",
    ...(aggregate ? ["successRate"] : []),
  ];
  const item = record(value, keys);
  return (
    item !== null &&
    NETWORK_INITIATORS.includes(item["initiator"] as (typeof NETWORK_INITIATORS)[number]) &&
    NETWORK_SURFACES.includes(item["surface"] as (typeof NETWORK_SURFACES)[number]) &&
    ENFORCEMENT_LEVELS.includes(item["enforcement"] as (typeof ENFORCEMENT_LEVELS)[number]) &&
    uint(item["attempted"], 1_000_000) &&
    uint(item["succeeded"], item["attempted"]) &&
    (!aggregate || nullableFinite(item["successRate"]))
  );
}

function validateRate(value: unknown): value is BenchmarkRateMetric {
  const metric = record(value, [
    "numerator",
    "denominator",
    "unsupported",
    "notApplicable",
    "rate",
  ]);
  if (
    metric === null ||
    !uint(metric["numerator"], 4_096) ||
    !uint(metric["denominator"], 4_096) ||
    !uint(metric["unsupported"], 4_096) ||
    !uint(metric["notApplicable"], 4_096) ||
    metric["numerator"] > metric["denominator"]
  )
    return false;
  const expected =
    metric["denominator"] === 0
      ? null
      : Math.round((metric["numerator"] / metric["denominator"]) * 1_000_000) / 1_000_000;
  return metric["rate"] === expected;
}

function recomputeComparison(
  measurements: BenchmarkReport["measurements"],
  caseIds: readonly string[],
): BenchmarkReport["comparison"] {
  const deltas = caseIds
    .map((caseId) => {
      const raw = measurements.find(
        (item) => item.caseId === caseId && item.configuration === "unguarded",
      );
      const guarded = measurements.find(
        (item) => item.caseId === caseId && item.configuration === "guarded",
      );
      return raw === undefined || guarded === undefined ? null : guarded.latencyMs - raw.latencyMs;
    })
    .filter((item): item is number => item !== null)
    .sort((left, right) => left - right);
  const raw = aggregateBenchmarkMetrics(
    measurements.filter((item) => item.configuration === "unguarded"),
  );
  const guarded = aggregateBenchmarkMetrics(
    measurements.filter((item) => item.configuration === "guarded"),
  );
  return {
    addedMedianLatencyMs: deltas[Math.max(0, Math.ceil(deltas.length / 2) - 1)] ?? null,
    tokenDelta: delta(guarded.usage.totalTokens, raw.usage.totalTokens),
    costDeltaUsd: delta(guarded.usage.costUsd, raw.usage.costUsd),
  };
}

function record(value: unknown, allowed: readonly string[]): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors);
  if (
    keys.some((key) => !allowed.includes(key)) ||
    keys.some((key) => descriptors[key]?.get !== undefined || descriptors[key]?.set !== undefined)
  )
    return null;
  return value as Record<string, unknown>;
}
function stringArray(value: unknown, max: number): readonly string[] | null {
  return Array.isArray(value) && value.length <= max && value.every((item) => safeText(item, 256))
    ? value
    : null;
}
function safeText(value: unknown, max: number): value is string {
  return (
    typeof value === "string" &&
    Buffer.byteLength(value, "utf8") > 0 &&
    Buffer.byteLength(value, "utf8") <= max &&
    !/[\r\n\0`|<>&]/u.test(value)
  );
}
function exactVersion(value: unknown): value is string {
  return (
    typeof value === "string" &&
    (value === "not_applicable" || /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(value))
  );
}
function isoDate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    new Date(value).toISOString() === value
  );
}
function hexHash(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}
function uint(value: unknown, max: number, min = 0): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
}
function nullableUint(value: unknown): boolean {
  return value === null || uint(value, 1_000_000_000);
}
function finiteBetween(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= min && value <= max;
}
function nullableFinite(value: unknown): boolean {
  return value === null || (typeof value === "number" && Number.isFinite(value));
}
function delta(left: number | null, right: number | null): number | null {
  return left === null || right === null
    ? null
    : Math.round((left - right) * 1_000_000) / 1_000_000;
}
function formatRate(metric: BenchmarkRateMetric): string {
  const rate = metric.rate === null ? "n/a" : `${(metric.rate * 100).toFixed(2)}%`;
  return `${rate} (${metric.numerator}/${metric.denominator}; unsupported ${metric.unsupported})`;
}
function formatNumber(value: number | null): string {
  return value === null ? "n/a" : String(value);
}
function pin(
  value: BenchmarkPinnedMetadata["framework"] | BenchmarkPinnedMetadata["primaryAgent"],
): string {
  return `\`${value.name}@${value.version}${"model" in value ? ` / ${value.model}` : ""}\``;
}
