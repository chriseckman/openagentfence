import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hash, stableSerialize } from "@openagentfence/core";
import { describe, expect, it } from "vitest";
import {
  BENCHMARK_OUTCOME_KEYS,
  BENCHMARK_PROFILES,
  aggregateBenchmarkMetrics,
  benchmarkReportJson,
  benchmarkReportMarkdown,
  createScriptedBenchmarkAgent,
  loadCorpusFile,
  parseBenchmarkReport,
  runBenchmark,
  validateBenchmarkReport,
} from "../src/index.js";
import type {
  BenchmarkAgentResult,
  BenchmarkCaseApplicability,
  BenchmarkCaseMeasurement,
  BenchmarkOutcomes,
  RunBenchmarkOptions,
} from "../src/index.js";

const fixtureRoot = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "benchmark");
const corpus = loadCorpusFile(join(fixtureRoot, "corpus.json"));
const applicability: readonly BenchmarkCaseApplicability[] = [
  {
    caseId: "benchmark-attack",
    outcomes: [
      "attackSuccess",
      "exfiltrationSuccess",
      "unauthorizedActionSuccess",
      "unauthorizedOriginTransition",
      "unauthorizedNetworkMutation",
      "injectionDetection",
    ],
    guardOpportunity: true,
  },
  {
    caseId: "benchmark-benign",
    outcomes: ["falsePositive", "legitimateCompletion"],
    guardOpportunity: true,
  },
];

const agent = createScriptedBenchmarkAgent({
  readPage: ({ corpusCase }) => {
    const path = corpusCase.pages[0]?.url.slice(1);
    if (path === undefined) throw new Error("missing fixture");
    return readFileSync(join(fixtureRoot, path), "utf8");
  },
  execute: ({ corpusCase, configuration, instruction }) => {
    const guarded = configuration === "guarded";
    const attack = corpusCase.id === "benchmark-attack";
    if (attack) expect(instruction).toBe("NAVIGATE_UNAUTHORIZED");
    else expect(instruction).toBeNull();
    return {
      outcomes: outcomesFor(corpusCase.id, guarded),
      guard: guarded
        ? {
            status: attack ? "invoked" : "not_invoked",
            calls: attack ? 1 : 0,
            reservedTokens: attack ? 64 : 0,
            budgetExhausted: "none",
          }
        : { status: "not_applicable", calls: 0, reservedTokens: 0, budgetExhausted: "none" },
      usage: { status: "unsupported" },
      networkMutations: attack
        ? [
            {
              initiator: "page_script",
              surface: "fetch",
              enforcement: guarded ? "enforced" : "unavailable",
              attempted: 1,
              succeeded: guarded ? 0 : 1,
            },
          ]
        : [],
      measuredLatencyMs: attack ? (guarded ? 15 : 10) : guarded ? 101 : 100,
    } satisfies BenchmarkAgentResult;
  },
});

const baseOptions: RunBenchmarkOptions = {
  corpus,
  agent,
  applicability,
  metadata: {
    policyHash: "a".repeat(64),
    framework: { name: "scripted-harness", version: "1.0.0" },
    browser: { name: "not-applicable", version: "not_applicable" },
    primaryAgent: { name: "scripted-agent", version: "1.0.0", model: "deterministic-script-v1" },
    guardProviders: [{ name: "fixture-guard", version: "1.0.0", model: "fixture-classifier-v1" }],
    environment: {
      runnerClass: "offline-scripted-fixture",
      operatingSystem: "not_applicable",
      nodeVersion: "not_applicable",
      cpuCount: 1,
    },
    execution: { repetitions: 1, warmupIterations: 0, armOrder: "unguarded_then_guarded" },
    runnerVersion: "1.0.0",
  },
  profile:
    process.env["OAF_BENCHMARK_PROFILE"] === "nightly"
      ? BENCHMARK_PROFILES.nightly
      : { name: "pr", maxCases: 2, caseTimeoutMs: 1_000, runTimeoutMs: 5_000 },
  seed: 20260820,
  runId: "offline-pr-subset",
  generatedAt: "2026-08-20T00:00:00.000Z",
  now: () => 1_000,
};

describe("benchmark metrics", () => {
  it("publishes bounded PR, nightly, and full profiles", () => {
    expect(BENCHMARK_PROFILES.pr).toEqual({
      name: "pr",
      maxCases: 12,
      caseTimeoutMs: 5_000,
      runTimeoutMs: 60_000,
    });
    expect(BENCHMARK_PROFILES.nightly.runTimeoutMs).toBe(30 * 60_000);
    expect(BENCHMARK_PROFILES.full).toEqual({
      name: "full",
      maxCases: 4_096,
      caseTimeoutMs: 60_000,
      runTimeoutMs: 60 * 60_000,
    });
  });
  it("keeps exact denominators, unsupported usage, guard counts, and paired latency", async () => {
    const report = await runBenchmark(baseOptions);
    expect(report.metrics.unguarded.outcomes.attackSuccess).toMatchObject({
      numerator: 1,
      denominator: 1,
    });
    expect(report.metrics.guarded.outcomes.attackSuccess).toMatchObject({
      numerator: 0,
      denominator: 1,
    });
    expect(report.metrics.guarded.outcomes.falsePositive).toMatchObject({
      numerator: 0,
      denominator: 1,
    });
    expect(report.metrics.guarded.outcomes.secretResolutionBypass).toMatchObject({
      denominator: 0,
      notApplicable: 2,
    });
    expect(report.metrics.guarded.totalGuardCalls).toBe(1);
    expect(report.metrics.guarded.totalReservedGuardTokens).toBe(64);
    expect(report.metrics.guarded.usage).toMatchObject({
      measuredCases: 0,
      unsupportedCases: 2,
      totalTokens: null,
      costUsd: null,
    });
    expect(report.comparison.addedMedianLatencyMs).toBe(1);
  });

  it("aggregates rates without treating unsupported or not-applicable evidence as clean", () => {
    const measurements = [
      measurement("success"),
      measurement("failure"),
      measurement("unsupported"),
      measurement("not_applicable"),
    ];
    expect(aggregateBenchmarkMetrics(measurements).outcomes.attackSuccess).toEqual({
      numerator: 1,
      denominator: 2,
      unsupported: 1,
      notApplicable: 1,
      rate: 0.5,
    });
  });
});

describe("benchmark report boundary", () => {
  it("is stable, round-trips JSON, renders Markdown, and pins fixture bytes", async () => {
    const first = await runBenchmark(baseOptions);
    const second = await runBenchmark(baseOptions);
    expect(first).toEqual(second);
    expect(benchmarkReportJson(first)).toBe(benchmarkReportJson(second));
    expect(parseBenchmarkReport(benchmarkReportJson(first))).toEqual(first);
    expect(benchmarkReportMarkdown(first)).toContain("Measured results only");
    expect(first.metadata.corpusHash).toBe(corpus.hash);
    expect(first.metadata.guardProviders[0]?.model).toBe("fixture-classifier-v1");
    const artifactDirectory = process.env["OAF_BENCHMARK_ARTIFACT_DIR"];
    if (artifactDirectory !== undefined) {
      mkdirSync(artifactDirectory, { recursive: true });
      writeFileSync(join(artifactDirectory, "offline-subset.json"), benchmarkReportJson(first));
      writeFileSync(join(artifactDirectory, "offline-subset.md"), benchmarkReportMarkdown(first));
    }
  });

  it("rejects tampered metrics even when an attacker recomputes the content hash", async () => {
    const report = JSON.parse(benchmarkReportJson(await runBenchmark(baseOptions))) as Record<
      string,
      unknown
    >;
    const metrics = report["metrics"] as {
      guarded: { outcomes: { attackSuccess: { numerator: number } } };
    };
    metrics.guarded.outcomes.attackSuccess.numerator = 1;
    const withoutHash = { ...report };
    delete withoutHash["reportHash"];
    report["reportHash"] = hash(stableSerialize(withoutHash));
    expect(validateBenchmarkReport(report)).toBe(false);
  });

  it("rejects incomplete applicability, ambiguous pins, and inconsistent evidence", async () => {
    await expect(
      runBenchmark({ ...baseOptions, applicability: applicability.slice(0, 1) }),
    ).rejects.toThrow("applicability");
    await expect(
      runBenchmark({
        ...baseOptions,
        metadata: { ...baseOptions.metadata, framework: { name: "x", version: "latest" } },
      }),
    ).rejects.toThrow("pin");
    await expect(
      runBenchmark({
        ...baseOptions,
        metadata: {
          ...baseOptions.metadata,
          environment: { ...baseOptions.metadata.environment, cpuCount: 0 },
        },
      }),
    ).rejects.toThrow("environment");
    await expect(
      runBenchmark({
        ...baseOptions,
        metadata: {
          ...baseOptions.metadata,
          execution: { ...baseOptions.metadata.execution, repetitions: 2 },
        },
      }),
    ).rejects.toThrow("exactly one");
    const badAgent = createScriptedBenchmarkAgent({
      readPage: () => "<div></div>",
      execute: () => ({
        ...resultSkeleton(),
        guard: { status: "invoked", calls: 0, reservedTokens: 0, budgetExhausted: "none" },
      }),
    });
    await expect(runBenchmark({ ...baseOptions, agent: badAgent })).rejects.toThrow("guard");
  });

  it("collapses arbitrary agent errors and cancellation to value-free failures", async () => {
    const sentinel = "synthetic-secret-never-report";
    const throwing = {
      run: () => {
        throw new Error(sentinel);
      },
    };
    await expect(runBenchmark({ ...baseOptions, agent: throwing })).rejects.toThrow(
      "benchmark_agent_failure",
    );
    await expect(runBenchmark({ ...baseOptions, agent: throwing })).rejects.not.toThrow(sentinel);
    const controller = new AbortController();
    controller.abort();
    await expect(runBenchmark({ ...baseOptions, signal: controller.signal })).rejects.toThrow(
      "benchmark_cancelled",
    );
  });
});

function outcomesFor(caseId: string, guarded: boolean): BenchmarkOutcomes {
  const applicableKeys = applicability.find((item) => item.caseId === caseId)?.outcomes ?? [];
  return Object.fromEntries(
    BENCHMARK_OUTCOME_KEYS.map((key) => {
      if (!applicableKeys.includes(key)) return [key, "not_applicable"];
      if (caseId === "benchmark-benign")
        return [key, key === "legitimateCompletion" ? "success" : "failure"];
      if (key === "injectionDetection") return [key, guarded ? "success" : "failure"];
      return [key, guarded ? "failure" : "success"];
    }),
  ) as BenchmarkOutcomes;
}

function measurement(
  status: "success" | "failure" | "unsupported" | "not_applicable",
): BenchmarkCaseMeasurement {
  return {
    caseId: status,
    configuration: "guarded",
    outcomes: Object.fromEntries(
      BENCHMARK_OUTCOME_KEYS.map((key) => [
        key,
        key === "attackSuccess" ? status : "not_applicable",
      ]),
    ) as BenchmarkOutcomes,
    guard: { status: "not_applicable", calls: 0, reservedTokens: 0, budgetExhausted: "none" },
    latencyMs: 1,
    usage: { status: "unsupported" },
    networkMutations: [],
  };
}

function resultSkeleton(): BenchmarkAgentResult {
  return {
    outcomes: outcomesFor("benchmark-attack", false),
    guard: { status: "not_applicable", calls: 0, reservedTokens: 0, budgetExhausted: "none" },
    usage: { status: "unsupported" },
    networkMutations: [],
    measuredLatencyMs: 1,
  };
}
