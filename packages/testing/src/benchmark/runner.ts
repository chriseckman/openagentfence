import {
  ENFORCEMENT_LEVELS,
  hash,
  NETWORK_INITIATORS,
  NETWORK_SURFACES,
  stableSerialize,
} from "@openagentfence/core";
import type { CorpusCase, LoadedCorpus } from "../corpus.js";
import {
  aggregateBenchmarkMetrics,
  BENCHMARK_OUTCOME_KEYS,
  type BenchmarkAggregateMetrics,
  type BenchmarkCaseMeasurement,
  type BenchmarkGuardMeasurement,
  type BenchmarkModelUsage,
  type BenchmarkNetworkMutationMeasurement,
  type BenchmarkOutcomes,
} from "./metrics.js";

export const BENCHMARK_SCHEMA_VERSION = "1.0.0";
export const BENCHMARK_LIMITS = Object.freeze({
  maxCases: 4_096,
  maxCaseDurationMs: 60_000,
  maxRunDurationMs: 60 * 60_000,
  maxIdentifierBytes: 256,
});

export const BENCHMARK_PROFILES = Object.freeze({
  pr: Object.freeze({
    name: "pr" as const,
    maxCases: 12,
    caseTimeoutMs: 5_000,
    runTimeoutMs: 60_000,
  }),
  nightly: Object.freeze({
    name: "nightly" as const,
    maxCases: 1_024,
    caseTimeoutMs: 30_000,
    runTimeoutMs: 30 * 60_000,
  }),
  full: Object.freeze({
    name: "full" as const,
    maxCases: 4_096,
    caseTimeoutMs: 60_000,
    runTimeoutMs: 60 * 60_000,
  }),
});

export interface BenchmarkComponentPin {
  readonly name: string;
  readonly version: string;
}

export interface BenchmarkModelPin extends BenchmarkComponentPin {
  readonly model: string;
}

export interface BenchmarkPinnedMetadata {
  readonly corpusHash: string;
  readonly corpusSchemaVersion: string;
  readonly policyHash: string;
  readonly framework: BenchmarkComponentPin;
  readonly browser: BenchmarkComponentPin;
  readonly primaryAgent: BenchmarkModelPin;
  readonly guardProviders: readonly BenchmarkModelPin[];
  readonly runnerVersion: string;
}

export interface BenchmarkProfile {
  readonly name: "pr" | "nightly" | "full" | "custom";
  readonly maxCases: number;
  readonly caseTimeoutMs: number;
  readonly runTimeoutMs: number;
}

/** Explicit metric population for one case; generic corpus tags never infer denominators. */
export interface BenchmarkCaseApplicability {
  readonly caseId: string;
  readonly outcomes: readonly (typeof BENCHMARK_OUTCOME_KEYS)[number][];
  readonly guardOpportunity: boolean;
}

export interface BenchmarkAgentInput {
  readonly corpusCase: CorpusCase;
  readonly configuration: "unguarded" | "guarded";
  readonly controlsEnabled: boolean;
  readonly seed: number;
  readonly signal: AbortSignal;
  readonly deadline: number;
}

export interface BenchmarkAgentResult {
  readonly outcomes: BenchmarkOutcomes;
  readonly guard: BenchmarkGuardMeasurement;
  readonly usage: BenchmarkModelUsage;
  readonly networkMutations: readonly BenchmarkNetworkMutationMeasurement[];
  /** Optional deterministic duration supplied by a scripted/offline agent. */
  readonly measuredLatencyMs?: number;
}

export interface BenchmarkAgent {
  run(input: BenchmarkAgentInput): Promise<BenchmarkAgentResult> | BenchmarkAgentResult;
}

export interface ScriptedBenchmarkHarness {
  /** Read bounded committed page/recording input; never return credentials. */
  readPage(input: BenchmarkAgentInput): Promise<string> | string;
  /** Execute the exact extracted page instruction and return measured evidence. */
  execute(
    input: BenchmarkAgentInput & { readonly pageText: string; readonly instruction: string | null },
  ): Promise<BenchmarkAgentResult> | BenchmarkAgentResult;
}

export interface BenchmarkComparison {
  readonly addedMedianLatencyMs: number | null;
  readonly tokenDelta: number | null;
  readonly costDeltaUsd: number | null;
}

export interface BenchmarkReport {
  readonly schemaVersion: typeof BENCHMARK_SCHEMA_VERSION;
  readonly runId: string;
  readonly generatedAt: string;
  readonly profile: BenchmarkProfile;
  readonly seed: number;
  readonly metadata: BenchmarkPinnedMetadata;
  readonly caseIds: readonly string[];
  readonly applicability: readonly BenchmarkCaseApplicability[];
  readonly measurements: readonly BenchmarkCaseMeasurement[];
  readonly metrics: Readonly<{
    unguarded: BenchmarkAggregateMetrics;
    guarded: BenchmarkAggregateMetrics;
  }>;
  readonly comparison: BenchmarkComparison;
  readonly reportHash: string;
}

export interface RunBenchmarkOptions {
  readonly corpus: LoadedCorpus;
  readonly agent: BenchmarkAgent;
  readonly metadata: Omit<BenchmarkPinnedMetadata, "corpusHash" | "corpusSchemaVersion">;
  readonly profile: BenchmarkProfile;
  readonly seed: number;
  readonly runId: string;
  readonly generatedAt: string;
  readonly caseIds?: readonly string[];
  readonly applicability: readonly BenchmarkCaseApplicability[];
  readonly signal?: AbortSignal;
  readonly now?: () => number;
}

/** Run identical corpus cases in unguarded and guarded configurations, sequentially. */
export async function runBenchmark(options: RunBenchmarkOptions): Promise<BenchmarkReport> {
  validateRunOptions(options);
  const selected = selectCases(options.corpus, options.caseIds, options.profile.maxCases);
  const applicability = validateApplicability(options.applicability, selected);
  const now = options.now ?? Date.now;
  const startedAt = now();
  const runDeadline = startedAt + options.profile.runTimeoutMs;
  const measurements: BenchmarkCaseMeasurement[] = [];

  for (const corpusCase of selected) {
    const caseApplicability = applicability.find((item) => item.caseId === corpusCase.id);
    if (caseApplicability === undefined)
      throw new TypeError("benchmark applicability is incomplete");
    for (const configuration of ["unguarded", "guarded"] as const) {
      if (options.signal?.aborted) throw new TypeError("benchmark_cancelled");
      const invocationStartedAt = now();
      const deadline = Math.min(runDeadline, invocationStartedAt + options.profile.caseTimeoutMs);
      if (deadline <= invocationStartedAt) throw new TypeError("benchmark_timeout");
      const controller = new AbortController();
      const onAbort = (): void => controller.abort();
      options.signal?.addEventListener("abort", onAbort, { once: true });
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const timeoutMs = Math.max(1, deadline - now());
        const timeout = new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new TypeError("benchmark_timeout"));
          }, timeoutMs);
        });
        let result: BenchmarkAgentResult;
        try {
          result = await Promise.race([
            options.agent.run({
              corpusCase,
              configuration,
              controlsEnabled: configuration === "guarded",
              seed: caseSeed(options.seed, corpusCase.id),
              signal: controller.signal,
              deadline,
            }),
            timeout,
          ]);
        } catch (error) {
          if (error instanceof TypeError && error.message === "benchmark_timeout") throw error;
          if (options.signal?.aborted) throw new TypeError("benchmark_cancelled");
          throw new TypeError("benchmark_agent_failure");
        }
        const latencyMs = result.measuredLatencyMs ?? Math.max(0, now() - invocationStartedAt);
        validateAgentResult(result, latencyMs, caseApplicability, configuration);
        measurements.push(
          Object.freeze({
            caseId: corpusCase.id,
            configuration,
            outcomes: Object.freeze({ ...result.outcomes }),
            guard: Object.freeze({ ...result.guard }),
            latencyMs,
            usage: Object.freeze({ ...result.usage }),
            networkMutations: Object.freeze(
              result.networkMutations.map((item) => Object.freeze({ ...item })),
            ),
          }),
        );
      } finally {
        if (timer !== undefined) clearTimeout(timer);
        options.signal?.removeEventListener("abort", onAbort);
        controller.abort();
      }
    }
  }

  const unguarded = aggregateBenchmarkMetrics(
    measurements.filter((item) => item.configuration === "unguarded"),
  );
  const guarded = aggregateBenchmarkMetrics(
    measurements.filter((item) => item.configuration === "guarded"),
  );
  const reportWithoutHash = Object.freeze({
    schemaVersion: BENCHMARK_SCHEMA_VERSION,
    runId: options.runId,
    generatedAt: options.generatedAt,
    profile: Object.freeze({ ...options.profile }),
    seed: options.seed,
    metadata: Object.freeze({
      ...options.metadata,
      corpusHash: options.corpus.hash,
      corpusSchemaVersion: options.corpus.schemaVersion,
    }),
    caseIds: Object.freeze(selected.map((item) => item.id)),
    applicability,
    measurements: Object.freeze(measurements),
    metrics: Object.freeze({ unguarded, guarded }),
    comparison: Object.freeze({
      addedMedianLatencyMs: pairedLatencyDelta(measurements, selected),
      tokenDelta: nullableDelta(guarded.usage.totalTokens, unguarded.usage.totalTokens),
      costDeltaUsd: nullableDelta(guarded.usage.costUsd, unguarded.usage.costUsd),
    }),
  });
  return Object.freeze({
    ...reportWithoutHash,
    reportHash: hash(stableSerialize(reportWithoutHash)),
  });
}

/** Stable per-case seed; both configurations receive the same value. */
export function caseSeed(seed: number, caseId: string): number {
  const digest = hash(`${seed}:${caseId}`).slice(0, 8);
  return Number.parseInt(digest, 16) >>> 0;
}

/** Create the deterministic scripted-agent seam used by offline CI fixtures. */
export function createScriptedBenchmarkAgent(harness: ScriptedBenchmarkHarness): BenchmarkAgent {
  return Object.freeze({
    run: async (input: BenchmarkAgentInput) => {
      const pageText = await harness.readPage(input);
      if (Buffer.byteLength(pageText, "utf8") > 256 * 1024) {
        throw new TypeError("scripted benchmark page exceeds the size limit");
      }
      const marker = /data-oaf-scripted-instruction=["']([^"']{1,2048})["']/iu.exec(pageText);
      return harness.execute({
        ...input,
        pageText,
        instruction: marker?.[1] ?? null,
      });
    },
  });
}

function selectCases(
  corpus: LoadedCorpus,
  caseIds: readonly string[] | undefined,
  maxCases: number,
): readonly CorpusCase[] {
  const ids = caseIds === undefined ? undefined : new Set(caseIds);
  if (ids !== undefined && ids.size !== caseIds?.length) {
    throw new TypeError("benchmark caseIds must be unique");
  }
  const selected = corpus.cases.filter((item) => ids === undefined || ids.has(item.id));
  if (ids !== undefined && selected.length !== ids.size)
    throw new TypeError("unknown benchmark caseId");
  if (selected.length === 0 || selected.length > maxCases) {
    throw new TypeError("benchmark selection is empty or exceeds maxCases");
  }
  return Object.freeze([...selected].sort((left, right) => left.id.localeCompare(right.id)));
}

function validateRunOptions(options: RunBenchmarkOptions): void {
  if (!Number.isInteger(options.seed) || options.seed < 0 || options.seed > 0xffff_ffff) {
    throw new TypeError("benchmark seed must be an unsigned 32-bit integer");
  }
  if (!boundedIdentifier(options.runId) || !validIsoDate(options.generatedAt)) {
    throw new TypeError("benchmark run identity is invalid");
  }
  const profile = options.profile;
  if (
    !["pr", "nightly", "full", "custom"].includes(profile.name) ||
    !integerBetween(profile.maxCases, 1, BENCHMARK_LIMITS.maxCases) ||
    !integerBetween(profile.caseTimeoutMs, 1, BENCHMARK_LIMITS.maxCaseDurationMs) ||
    !integerBetween(profile.runTimeoutMs, profile.caseTimeoutMs, BENCHMARK_LIMITS.maxRunDurationMs)
  ) {
    throw new TypeError("benchmark profile is invalid or unbounded");
  }
  if (options.corpus.hash.length !== 64) throw new TypeError("benchmark corpus hash is invalid");
  if (options.metadata.policyHash.length !== 64)
    throw new TypeError("benchmark policy hash is invalid");
  for (const pin of [
    options.metadata.framework,
    options.metadata.browser,
    options.metadata.primaryAgent,
    ...options.metadata.guardProviders,
  ]) {
    if (!boundedIdentifier(pin.name) || !exactVersion(pin.version)) {
      throw new TypeError("benchmark component pin is invalid");
    }
  }
  if (options.metadata.guardProviders.length === 0 || options.metadata.guardProviders.length > 8) {
    throw new TypeError("benchmark guard provider pins are missing or unbounded");
  }
  for (const pin of [options.metadata.primaryAgent, ...options.metadata.guardProviders]) {
    if (!boundedIdentifier(pin.model) || /^(?:latest|default|auto)$/iu.test(pin.model)) {
      throw new TypeError("benchmark model pin is invalid");
    }
  }
  if (!boundedIdentifier(options.metadata.runnerVersion)) {
    throw new TypeError("benchmark runner version is invalid");
  }
}

function validateAgentResult(
  result: BenchmarkAgentResult,
  latencyMs: number,
  applicability: BenchmarkCaseApplicability,
  configuration: "unguarded" | "guarded",
): void {
  const statuses = new Set(["success", "failure", "not_applicable", "unsupported"]);
  if (
    Object.keys(result.outcomes).length !== BENCHMARK_OUTCOME_KEYS.length ||
    BENCHMARK_OUTCOME_KEYS.some((key) => !statuses.has(result.outcomes[key])) ||
    !finiteNonNegative(latencyMs) ||
    latencyMs > BENCHMARK_LIMITS.maxCaseDurationMs ||
    !integerBetween(result.guard.calls, 0, 1_000_000) ||
    !integerBetween(result.guard.reservedTokens, 0, 1_000_000_000) ||
    !["none", "calls", "tokens", "calls_and_tokens"].includes(result.guard.budgetExhausted) ||
    !["invoked", "not_invoked", "not_applicable", "unsupported"].includes(result.guard.status)
  ) {
    throw new TypeError("benchmark agent returned malformed or unbounded evidence");
  }
  if (
    result.networkMutations.length > 128 ||
    result.networkMutations.some(
      (item) =>
        !NETWORK_INITIATORS.includes(item.initiator) ||
        !NETWORK_SURFACES.includes(item.surface) ||
        !ENFORCEMENT_LEVELS.includes(item.enforcement) ||
        !integerBetween(item.attempted, 0, 1_000_000) ||
        !integerBetween(item.succeeded, 0, item.attempted),
    )
  )
    throw new TypeError("benchmark network mutation evidence is malformed or unbounded");
  for (const key of BENCHMARK_OUTCOME_KEYS) {
    const applicable = applicability.outcomes.includes(key);
    if ((result.outcomes[key] === "not_applicable") === applicable) {
      throw new TypeError(`benchmark outcome applicability mismatch: ${key}`);
    }
  }
  if (configuration === "unguarded" && result.guard.status !== "not_applicable") {
    throw new TypeError("unguarded benchmark arm cannot invoke the security guard");
  }
  if (
    configuration === "guarded" &&
    ((applicability.guardOpportunity && result.guard.status === "not_applicable") ||
      (!applicability.guardOpportunity && result.guard.status !== "not_applicable"))
  ) {
    throw new TypeError("benchmark guard applicability mismatch");
  }
  if (
    (result.guard.status === "invoked" && result.guard.calls < 1) ||
    (result.guard.status !== "invoked" && result.guard.calls !== 0) ||
    (["not_applicable", "unsupported"].includes(result.guard.status) &&
      result.guard.budgetExhausted !== "none")
  ) {
    throw new TypeError("benchmark guard measurement is inconsistent");
  }
  if (
    result.usage.status === "measured" &&
    ![result.usage.inputTokens, result.usage.outputTokens].every(
      (value) => value !== undefined && integerBetween(value, 0, 1_000_000_000),
    )
  ) {
    throw new TypeError("benchmark measured usage requires bounded token counts");
  }
  if (
    result.usage.status === "unsupported" &&
    (result.usage.inputTokens !== undefined ||
      result.usage.outputTokens !== undefined ||
      result.usage.costUsd !== undefined)
  ) {
    throw new TypeError("unsupported benchmark usage cannot carry measured values");
  }
  if (
    result.usage.costUsd !== undefined &&
    (!finiteNonNegative(result.usage.costUsd) || result.usage.costUsd > 1_000_000)
  ) {
    throw new TypeError("benchmark cost is invalid or unbounded");
  }
}

function validateApplicability(
  entries: readonly BenchmarkCaseApplicability[],
  cases: readonly CorpusCase[],
): readonly BenchmarkCaseApplicability[] {
  if (entries.length !== cases.length) throw new TypeError("benchmark applicability is incomplete");
  const output = entries.map((entry) => {
    if (
      !cases.some((item) => item.id === entry.caseId) ||
      new Set(entry.outcomes).size !== entry.outcomes.length ||
      entry.outcomes.some((key) => !BENCHMARK_OUTCOME_KEYS.includes(key))
    )
      throw new TypeError("benchmark applicability is invalid");
    return Object.freeze({
      caseId: entry.caseId,
      outcomes: Object.freeze([...entry.outcomes].sort()),
      guardOpportunity: entry.guardOpportunity,
    });
  });
  if (new Set(output.map((entry) => entry.caseId)).size !== output.length) {
    throw new TypeError("benchmark applicability contains duplicate cases");
  }
  return Object.freeze(output.sort((left, right) => left.caseId.localeCompare(right.caseId)));
}

function nullableDelta(left: number | null, right: number | null): number | null {
  return left === null || right === null
    ? null
    : Math.round((left - right) * 1_000_000) / 1_000_000;
}

function boundedIdentifier(value: string): boolean {
  const bytes = Buffer.byteLength(value, "utf8");
  return bytes > 0 && bytes <= BENCHMARK_LIMITS.maxIdentifierBytes && !/[\r\n\0`|<>&]/u.test(value);
}

function exactVersion(value: string): boolean {
  return value === "not_applicable" || /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(value);
}

function pairedLatencyDelta(
  measurements: readonly BenchmarkCaseMeasurement[],
  cases: readonly CorpusCase[],
): number | null {
  const deltas = cases
    .map((item) => {
      const guarded = measurements.find(
        (measurement) => measurement.caseId === item.id && measurement.configuration === "guarded",
      );
      const unguarded = measurements.find(
        (measurement) =>
          measurement.caseId === item.id && measurement.configuration === "unguarded",
      );
      return guarded === undefined || unguarded === undefined
        ? null
        : guarded.latencyMs - unguarded.latencyMs;
    })
    .filter((value): value is number => value !== null)
    .sort((left, right) => left - right);
  if (deltas.length === 0) return null;
  return deltas[Math.max(0, Math.ceil(deltas.length / 2) - 1)] ?? null;
}

function finiteNonNegative(value: number): boolean {
  return Number.isFinite(value) && value >= 0;
}

function integerBetween(value: number, min: number, max: number): boolean {
  return Number.isInteger(value) && value >= min && value <= max;
}

function validIsoDate(value: string): boolean {
  return (
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    new Date(value).toISOString() === value
  );
}
