/**
 * @packageDocumentation
 * Offline test support only; this experimental package is not a production
 * runtime dependency.
 * @experimental
 */
export const PACKAGE_NAME = "@openagentfence/testing";

export { FIXTURE_SERVER_LIMITS, startFixtureServer, fixtureSentinel } from "./fixture-server.js";
export type {
  FixtureOrigin,
  CapturedRequest,
  FixtureServer,
  FixtureServerOptions,
} from "./fixture-server.js";

export {
  CORPUS_SCHEMA_VERSION,
  CORPUS_LIMITS,
  CORPUS_ATTACK_CLASSES,
  CORPUS_INVARIANTS,
  CORPUS_SURFACES,
  CORPUS_INITIATORS,
  validateCorpusCase,
  corpusHash,
  loadCorpusDocument,
  loadCorpusFile,
  corpusVitestCases,
  runCorpusCases,
} from "./corpus.js";
export type {
  CorpusAdaptiveMetadata,
  CorpusCase,
  CorpusExpected,
  CorpusInitiator,
  CorpusJson,
  CorpusJsonObject,
  CorpusMode,
  CorpusKind,
  CorpusMutationMetadata,
  CorpusPage,
  CorpusRunResult,
  CorpusStep,
  CorpusSurface,
  LoadedCorpus,
} from "./corpus.js";

export {
  expectNoRawSecret,
  expectNoRawSecretIn,
  expectBlocked,
  expectFinding,
  expectVerdict,
  hasFindingCategory,
  isBlockingVerdict,
  reasonsOf,
} from "./assertions.js";

export { BENCHMARK_OUTCOME_KEYS, aggregateBenchmarkMetrics } from "./benchmark/metrics.js";
export type {
  BenchmarkOutcomeKey,
  BenchmarkOutcomeStatus,
  BenchmarkOutcomes,
  BenchmarkGuardMeasurement,
  BenchmarkModelUsage,
  BenchmarkNetworkMutationMeasurement,
  BenchmarkNetworkMutationMetric,
  BenchmarkRateMetric,
  BenchmarkLatencyMetric,
  BenchmarkUsageMetric,
  BenchmarkAggregateMetrics,
  BenchmarkCaseMeasurement,
} from "./benchmark/metrics.js";
export {
  BENCHMARK_SCHEMA_VERSION,
  BENCHMARK_LIMITS,
  BENCHMARK_PROFILES,
  runBenchmark,
  caseSeed,
  createScriptedBenchmarkAgent,
} from "./benchmark/runner.js";
export type {
  BenchmarkComponentPin,
  BenchmarkModelPin,
  BenchmarkEnvironmentPin,
  BenchmarkExecutionPin,
  BenchmarkPinnedMetadata,
  BenchmarkProfile,
  BenchmarkCaseApplicability,
  BenchmarkAgentInput,
  BenchmarkAgentResult,
  BenchmarkAgent,
  ScriptedBenchmarkHarness,
  BenchmarkComparison,
  BenchmarkReport,
  RunBenchmarkOptions,
} from "./benchmark/runner.js";
export {
  benchmarkReportJson,
  parseBenchmarkReport,
  validateBenchmarkReport,
  benchmarkReportMarkdown,
} from "./benchmark/report.js";
