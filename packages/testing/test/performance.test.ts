import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import { dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_NETWORK_CAPABILITIES,
  OpenAgentFence,
  compileTaskContract,
  evaluateNetworkMutation,
  secureDefaultPolicyEngine,
  validateTaskContract,
  type BrowserAdapter,
  type PageObservation,
} from "@openagentfence/core";
import { createByokInjectionScannerFactory, defaultScanners } from "@openagentfence/scanners";
import { describe, expect, it } from "vitest";
import { loadCorpusFile } from "../src/index.js";

/**
 * This is a post-snapshot replay benchmark: fixture bytes are fed into a
 * bounded ProbeResult, so browser navigation and DOM snapshot collection are
 * intentionally outside the measured deterministic scan interval.
 */
const REPLAY_REPETITIONS = 7;
const WARMUP_FIXTURES = 5;
const AUTHORIZATION_REPETITIONS = 120;
const NETWORK_REPETITIONS = 500;
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const corpusPath = join(repoRoot, "security-corpus", "corpus.json");
const corpusRoot = dirname(corpusPath);
const corpus = loadCorpusFile(corpusPath);
const fixturePaths = Object.keys(corpus.fixtureHashes);
const fixtureTexts = fixturePaths.map((path) =>
  readFileSync(join(corpusRoot, path.slice(1)), "utf8"),
);

interface TimingSummary {
  readonly count: number;
  readonly medianMs: number;
  readonly p95Ms: number;
  readonly meanMs: number;
  readonly minMs: number;
  readonly maxMs: number;
  readonly standardDeviationMs: number;
}

interface PerformanceEvidence {
  readonly generatedAt: string;
  readonly corpusHash: string;
  readonly corpusSchemaVersion: string;
  readonly configuration: {
    readonly fixtureCount: number;
    readonly replayRepetitions: number;
    readonly warmupFixtures: number;
    readonly authorizationRepetitions: number;
    readonly networkRepetitions: number;
    readonly scanners: readonly string[];
    readonly policyHash: string;
  };
  readonly environment: {
    readonly runnerClass: string;
    readonly os: string;
    readonly node: string;
    readonly cpuCount: number;
    readonly cpuModel: string;
  };
  readonly deterministicPageScan: TimingSummary;
  readonly highImpactPreActionAuthorization: TimingSummary;
  readonly networkGuardEvaluation: TimingSummary;
  readonly benign: {
    readonly corpusCases: number;
    readonly completedObservations: number;
    readonly hardBlocks: number;
    readonly hardBlockRate: number;
    readonly semanticProviderInvocations: number;
    readonly semanticInvocationRate: number;
  };
}

describe("M8 post-snapshot performance evidence", () => {
  it("measures bounded real controls and detects material regressions", async () => {
    const deterministicPageScan = await measureDeterministicPageScans();
    const highImpactPreActionAuthorization = await measurePreActionAuthorization();
    const networkGuardEvaluation = measureNetworkGuard();
    const benign = await measureBenignScanOutcomes();
    const evidence: PerformanceEvidence = {
      generatedAt: new Date().toISOString(),
      corpusHash: corpus.hash,
      corpusSchemaVersion: corpus.schemaVersion,
      configuration: {
        fixtureCount: fixturePaths.length,
        replayRepetitions: REPLAY_REPETITIONS,
        warmupFixtures: WARMUP_FIXTURES,
        authorizationRepetitions: AUTHORIZATION_REPETITIONS,
        networkRepetitions: NETWORK_REPETITIONS,
        scanners: defaultScanners().map((scanner) => scanner.id),
        policyHash: secureDefaultPolicyEngine.policyHash,
      },
      environment: runtimeEnvironment(),
      deterministicPageScan,
      highImpactPreActionAuthorization,
      networkGuardEvaluation,
      benign,
    };

    // These are regression ceilings, intentionally not PRD pass/fail gates.
    // The PRD targets remain reported separately in docs with their measured
    // status on this pinned run.
    expect(deterministicPageScan.medianMs).toBeLessThan(500);
    expect(deterministicPageScan.p95Ms).toBeLessThan(1_500);
    expect(highImpactPreActionAuthorization.medianMs).toBeLessThan(250);
    expect(highImpactPreActionAuthorization.p95Ms).toBeLessThan(750);
    expect(networkGuardEvaluation.p95Ms).toBeLessThan(100);
    expect(benign.completedObservations).toBe(benign.corpusCases);
    expect(benign.hardBlocks).toBe(0);
    expect(benign.semanticProviderInvocations).toBeLessThan(benign.corpusCases / 2);

    writeArtifact(evidence);
    console.info(`OAF_M8_PERFORMANCE=${JSON.stringify(evidence)}`);
  }, 120_000);
});

async function measureDeterministicPageScans(): Promise<TimingSummary> {
  const samples: number[] = [];
  for (const [index, text] of fixtureTexts.slice(0, WARMUP_FIXTURES).entries()) {
    await observeSnapshot(snapshotFor(text, fixturePaths[index] ?? "/warmup.html", index));
  }
  for (let repetition = 0; repetition < REPLAY_REPETITIONS; repetition += 1) {
    for (const [index, text] of fixtureTexts.entries()) {
      const snapshot = snapshotFor(text, fixturePaths[index] ?? "/fixture.html", index);
      const startedAt = performance.now();
      await observeSnapshot(snapshot);
      samples.push(performance.now() - startedAt);
    }
  }
  return summarize(samples);
}

async function measurePreActionAuthorization(): Promise<TimingSummary> {
  const samples: number[] = [];
  const snapshot = snapshotFor("<main>benchmark</main>", "/authorization.html", 0);
  for (let index = 0; index < AUTHORIZATION_REPETITIONS; index += 1) {
    const session = new OpenAgentFence({
      adapter: adapterFor(snapshot),
      scanners: defaultScanners(),
    }).start({ task: "Delete one disposable benchmark record" });
    const startedAt = performance.now();
    const decision = await session.authorize({
      type: "DELETE",
      target: { element: "#benchmark-record", origin: snapshot.origin },
      instructionProvenance: { trust: "application" },
    });
    samples.push(performance.now() - startedAt);
    // No approval handler is configured: a high-impact operation must not
    // become executable merely because the benchmark is measuring it.
    expect(["BLOCK", "REQUIRE_APPROVAL"]).toContain(decision.verdict);
    await session.end();
  }
  return summarize(samples);
}

function measureNetworkGuard(): TimingSummary {
  const contract = {
    task: "Benchmark network guard",
    capabilities: {
      privateNetwork: false,
      navigation: "allowlist" as const,
      externalCommunication: true,
    },
    origins: { allow: ["https://benchmark.example"] },
  };
  const validated = validateTaskContract(contract);
  if (!validated.ok) throw new TypeError("benchmark network task contract is invalid");
  const envelope = compileTaskContract(validated.value);
  const input = {
    mutation: {
      surface: "fetch" as const,
      initiator: "page_script" as const,
      origin: "https://benchmark.example",
      destination: "https://benchmark.example/api",
      enforcement: "enforced" as const,
      provenance: { trust: "web" as const, timestamp: "2026-08-21T00:00:00.000Z" },
    },
    envelope,
    riskState: "NORMAL" as const,
    egressInspection: { verdict: "allow" as const, reasons: [], inspectedBytes: 0, matchCount: 0 },
  };
  for (let index = 0; index < 25; index += 1) evaluateNetworkMutation(input);
  const samples: number[] = [];
  for (let index = 0; index < NETWORK_REPETITIONS; index += 1) {
    const startedAt = performance.now();
    const decision = evaluateNetworkMutation(input);
    samples.push(performance.now() - startedAt);
    expect(decision.verdict).toBe("continue");
  }
  return summarize(samples);
}

async function measureBenignScanOutcomes(): Promise<PerformanceEvidence["benign"]> {
  const benignCases = corpus.cases.filter((item) => item.mode === "benign");
  let hardBlocks = 0;
  let semanticProviderInvocations = 0;
  let completedObservations = 0;
  for (const [index, corpusCase] of benignCases.entries()) {
    const path = corpusCase.pages[0]?.url.split(/[?#]/u, 1)[0];
    if (path === undefined) throw new TypeError("benchmark benign case has no fixture");
    const text = readFileSync(join(corpusRoot, path.slice(1)), "utf8");
    const snapshot = snapshotFor(text, path, index);
    const firewall = new OpenAgentFence({
      adapter: adapterFor(snapshot),
      scanners: defaultScanners(),
      guardScannerFactories: [createByokInjectionScannerFactory()],
      guardModel: {
        name: "offline-benchmark-guard",
        model: "deterministic-none",
        makesExternalCalls: false,
        classify: async () => {
          semanticProviderInvocations += 1;
          return {
            promptInjection: false,
            confidence: 1,
            categories: [],
            recommendedVerdict: "allow",
          };
        },
      },
    });
    const session = firewall.start({ task: corpusCase.task });
    const result = await session.observe();
    if (["BLOCK", "QUARANTINE"].includes(result.assessment.verdict)) hardBlocks += 1;
    completedObservations += 1;
    await session.end();
  }
  return {
    corpusCases: benignCases.length,
    completedObservations,
    hardBlocks,
    hardBlockRate: benignCases.length === 0 ? 0 : hardBlocks / benignCases.length,
    semanticProviderInvocations,
    semanticInvocationRate:
      benignCases.length === 0 ? 0 : semanticProviderInvocations / benignCases.length,
  };
}

async function observeSnapshot(snapshot: PageObservation): Promise<void> {
  const session = new OpenAgentFence({
    adapter: adapterFor(snapshot),
    scanners: defaultScanners(),
  }).start({ task: "Inspect this committed corpus replay" });
  await session.observe();
  await session.end();
}

function snapshotFor(text: string, path: string, index: number): PageObservation {
  const origin = "https://benchmark.example";
  const pageId = `benchmark-page-${index}`;
  const provenance = {
    trust: "web" as const,
    origin,
    frameOrigin: origin,
    pageId,
    elementId: `fixture-${index}`,
    timestamp: "2026-08-21T00:00:00.000Z",
  };
  return {
    url: `${origin}${path}`,
    origin,
    pageId,
    contextId: "benchmark-context",
    revision: 1,
    frames: [],
    provenance,
    probe: {
      probeVersion: 2,
      truncated: false,
      truncation: {
        nodes: false,
        textBytes: false,
        comments: false,
        metadata: false,
        links: false,
        time: false,
      },
      nodes: [
        {
          selector: `#fixture-${index}`,
          tagName: "article",
          text,
          display: "block",
          visibility: "visible",
          opacity: 1,
          ariaHidden: false,
          hidden: false,
          role: null,
          ariaLabel: null,
          ariaDescription: null,
          attributes: {},
          dimensions: { x: 0, y: 0, width: 100, height: 20 },
          boundingBox: { x: 0, y: 0, width: 100, height: 20 },
          frameOrigin: origin,
          fontSize: "16px",
          color: "rgb(0, 0, 0)",
          backgroundColor: "rgb(255, 255, 255)",
          position: "static",
          transform: "none",
          clipPath: "none",
          overflow: "visible",
          inViewport: true,
          pseudoBefore: null,
          pseudoAfter: null,
        },
      ],
      comments: [],
      metadata: { title: "", meta: {}, jsonLd: [], noscript: [] },
      links: [],
    },
  };
}

function adapterFor(observation: PageObservation): BrowserAdapter {
  return {
    capabilities: {
      route: false,
      network: DEFAULT_NETWORK_CAPABILITIES,
      navigationEvents: true,
      downloadEvents: true,
      popupEvents: true,
      screenshot: false,
      ariaSnapshot: false,
    },
    observe: async () => observation,
    executeAuthorized: async () => undefined,
    subscribe: () => () => {},
    rawPage: () => ({ benchmark: true }),
  };
}

function summarize(values: readonly number[]): TimingSummary {
  if (values.length === 0) throw new TypeError("benchmark collected no timing samples");
  const sorted = [...values].sort((left, right) => left - right);
  const mean = values.reduce((total, value) => total + value, 0) / values.length;
  const variance = values.reduce((total, value) => total + (value - mean) ** 2, 0) / values.length;
  return {
    count: values.length,
    medianMs: round(percentile(sorted, 0.5)),
    p95Ms: round(percentile(sorted, 0.95)),
    meanMs: round(mean),
    minMs: round(sorted[0] ?? 0),
    maxMs: round(sorted.at(-1) ?? 0),
    standardDeviationMs: round(Math.sqrt(variance)),
  };
}

function percentile(sorted: readonly number[], percentileValue: number): number {
  const index = Math.max(0, Math.ceil(sorted.length * percentileValue) - 1);
  return sorted[index] ?? 0;
}

function round(value: number): number {
  return Math.round(value * 1_000) / 1_000;
}

function runtimeEnvironment(): PerformanceEvidence["environment"] {
  const cpu = os.cpus()[0]?.model ?? "unknown";
  return {
    runnerClass: process.env["GITHUB_ACTIONS"] === "true" ? "github-actions" : "local-node",
    os: `${process.platform}-${process.arch}`,
    node: process.version,
    cpuCount: os.cpus().length,
    cpuModel: cpu
      .replace(/[\r\n\0`|<>&]/gu, " ")
      .trim()
      .slice(0, 256),
  };
}

function writeArtifact(evidence: PerformanceEvidence): void {
  const artifactDirectory = process.env["OAF_BENCHMARK_ARTIFACT_DIR"];
  if (artifactDirectory === undefined) return;
  mkdirSync(artifactDirectory, { recursive: true });
  writeFileSync(
    join(artifactDirectory, "m8-performance.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
  );
}
