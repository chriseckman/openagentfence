import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  CORPUS_ATTACK_CLASSES,
  loadCorpusFile,
  type CorpusCase,
  type LoadedCorpus,
} from "@openagentfence/testing";

const REPORTER_NAMES = new Set(["text", "json", "junit"]);
const REPORT_REASON_CODES = new Set([
  "action_intent_mismatch",
  "action_intent_mismatch_missing",
  "bound_sink_execution_failed",
  "corpus_case_failed",
  "corpus_executor_failed",
  "corpus_fixture_unavailable",
  "escape_hatch_unrecorded",
  "expected_finding_missing",
  "expected_reason_missing",
  "guard_failure_missing",
  "invalid_trace",
  "memory_read_invalid",
  "memory_read_unexpectedly_allowed",
  "memory_write_denied",
  "network_block_missing",
  "network_gap_missing",
  "plugin_execution_failed",
  "plugin_fixture_unavailable",
  "popup_containment_missing",
  "required_guard_not_contained",
  "semantic_authority_violation",
  "unexpected_allow",
  "unexpected_allow_sanitized",
  "unexpected_block",
  "unexpected_guard_failure",
  "unexpected_restrict",
  "unexpected_verdict",
  "unsupported_corpus_case",
]);
export const CORPUS_EXIT = Object.freeze({ success: 0, regression: 1, usage: 2 });

/** A local execution prerequisite is unavailable; its cause is never rendered. */
export class CorpusRuntimeUnavailableError extends Error {
  readonly code = "corpus_runtime_unavailable" as const;

  constructor() {
    super("corpus runtime unavailable");
    this.name = "CorpusRuntimeUnavailableError";
  }
}

export type CorpusReporter = "text" | "json" | "junit";
export type CorpusCaseStatus = "passed" | "failed";

export interface CorpusCaseResult {
  readonly id: string;
  readonly status: CorpusCaseStatus;
  readonly reasons: readonly string[];
  readonly durationMs: number;
}

export interface CorpusExecutor {
  execute(item: CorpusCase): Promise<Omit<CorpusCaseResult, "id" | "durationMs">>;
  close?(): Promise<void>;
}

export interface CorpusRunReport {
  readonly schemaVersion: "1.0.0";
  readonly corpusHash: string;
  readonly selectedClasses: readonly string[];
  readonly cases: readonly CorpusCaseResult[];
  readonly totals: { readonly total: number; readonly passed: number; readonly failed: number };
  readonly classTotals: Readonly<
    Record<string, { readonly total: number; readonly failed: number }>
  >;
}

export interface CorpusCommandIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly now?: () => number;
  readonly ci?: boolean;
}

export interface CorpusCommandDependencies {
  readonly createExecutor: (corpus: LoadedCorpus, manifestPath: string) => Promise<CorpusExecutor>;
}

interface ParsedArgs {
  readonly corpusPath: string;
  readonly classFilter?: string;
  readonly reporter: CorpusReporter;
  readonly output?: string;
}

/** Execute a strict corpus command. Security evaluation is delegated to the injected executor. */
export async function runCorpusCommand(
  args: readonly string[],
  io: CorpusCommandIo,
  dependencies: CorpusCommandDependencies,
): Promise<number> {
  const parsed = parseCorpusArgs(args, io.ci === true);
  if (parsed === null) {
    io.stderr(
      "usage: openagentfence test --corpus <directory|manifest> [--filter class=A1] [--reporter text|json|junit] [--output <file>]\n",
    );
    return CORPUS_EXIT.usage;
  }

  const manifestPath = resolveCorpusManifest(parsed.corpusPath);
  let corpus: LoadedCorpus;
  try {
    corpus = loadCorpusFile(manifestPath);
  } catch {
    io.stderr("corpus input is invalid or unavailable\n");
    return CORPUS_EXIT.usage;
  }

  const selected = corpus.cases.filter(
    (item) => parsed.classFilter === undefined || item.attackClasses.includes(parsed.classFilter),
  );
  if (selected.length === 0) {
    io.stderr("corpus filter selected no cases\n");
    return CORPUS_EXIT.usage;
  }
  const classesToVerify =
    parsed.classFilter === undefined ? CORPUS_ATTACK_CLASSES : [parsed.classFilter];
  const missingDeterministicClass = classesToVerify.find(
    (attackClass) =>
      !selected.some(
        (item) => item.attackClasses.includes(attackClass) && isDeterministicControl(item),
      ),
  );
  if (missingDeterministicClass !== undefined) {
    io.stderr(`corpus class ${missingDeterministicClass} has no deterministic control\n`);
    return CORPUS_EXIT.regression;
  }

  const now = io.now ?? Date.now;
  let executor: CorpusExecutor | undefined;
  try {
    executor = await dependencies.createExecutor(corpus, manifestPath);
    const cases: CorpusCaseResult[] = [];
    for (const item of selected) {
      const started = now();
      try {
        const result = await executor.execute(item);
        cases.push(
          Object.freeze({
            id: item.id,
            status: result.status,
            reasons: sanitizeReasons(result.status, result.reasons),
            durationMs: boundedDuration(now() - started),
          }),
        );
      } catch {
        cases.push(
          Object.freeze({
            id: item.id,
            status: "failed",
            reasons: ["corpus_executor_failed"],
            durationMs: boundedDuration(now() - started),
          }),
        );
      }
    }
    const report = buildReport(corpus, selected, cases, parsed.classFilter);
    const rendered = renderReport(report, parsed.reporter);
    if (parsed.output !== undefined) {
      await mkdir(dirname(resolve(parsed.output)), { recursive: true });
      await writeFile(resolve(parsed.output), rendered, "utf8");
    } else {
      io.stdout(rendered);
    }
    return report.totals.failed === 0 ? CORPUS_EXIT.success : CORPUS_EXIT.regression;
  } catch (error) {
    io.stderr(
      error instanceof CorpusRuntimeUnavailableError
        ? "corpus runtime unavailable\n"
        : "corpus command failed before execution\n",
    );
    return CORPUS_EXIT.usage;
  } finally {
    await executor?.close?.().catch(() => undefined);
  }
}

export function parseCorpusArgs(args: readonly string[], ci: boolean): ParsedArgs | null {
  let corpusPath: string | undefined;
  let classFilter: string | undefined;
  let reporter: CorpusReporter = "text";
  let output: string | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--update-snapshots") return null;
    if (
      argument === "--corpus" ||
      argument === "--filter" ||
      argument === "--reporter" ||
      argument === "--output"
    ) {
      const value = args[index + 1];
      if (value === undefined || value.startsWith("--")) return null;
      index += 1;
      if (argument === "--corpus") corpusPath = value;
      if (argument === "--filter") {
        const match = /^class=(A(?:[1-9]|1\d|20))$/u.exec(value);
        if (match?.[1] === undefined) return null;
        classFilter = match[1];
      }
      if (argument === "--reporter") {
        if (!REPORTER_NAMES.has(value)) return null;
        reporter = value as CorpusReporter;
      }
      if (argument === "--output") output = value;
      continue;
    }
    if (argument === "--ci" && ci) continue;
    return null;
  }
  if (corpusPath === undefined) return null;
  return Object.freeze({
    corpusPath,
    ...(classFilter === undefined ? {} : { classFilter }),
    reporter,
    ...(output === undefined ? {} : { output }),
  });
}

export function resolveCorpusManifest(input: string): string {
  return input.endsWith(".json") ? input : resolve(input, "corpus.json");
}

export function buildReport(
  corpus: LoadedCorpus,
  selected: readonly CorpusCase[],
  results: readonly CorpusCaseResult[],
  classFilter: string | undefined,
): CorpusRunReport {
  const byId = new Map(results.map((result) => [result.id, result]));
  if (byId.size !== selected.length || results.length !== selected.length) {
    throw new TypeError("corpus executor did not produce exactly one result per selected case");
  }
  const classTotals: Record<string, { total: number; failed: number }> = Object.create(
    null,
  ) as Record<string, { total: number; failed: number }>;
  for (const item of selected) {
    const result = byId.get(item.id);
    if (result === undefined) throw new TypeError("corpus result missing selected case");
    for (const attackClass of item.attackClasses) {
      const current = classTotals[attackClass] ?? { total: 0, failed: 0 };
      classTotals[attackClass] = {
        total: current.total + 1,
        failed: current.failed + (result.status === "failed" ? 1 : 0),
      };
    }
  }
  const totals = Object.freeze({
    total: results.length,
    passed: results.filter((item) => item.status === "passed").length,
    failed: results.filter((item) => item.status === "failed").length,
  });
  return Object.freeze({
    schemaVersion: "1.0.0",
    corpusHash: corpus.hash,
    selectedClasses: Object.freeze(
      classFilter === undefined ? Object.keys(classTotals).sort() : [classFilter],
    ),
    cases: Object.freeze([...results].sort((left, right) => left.id.localeCompare(right.id))),
    totals,
    classTotals: Object.freeze(
      Object.fromEntries(Object.entries(classTotals).sort(([a], [b]) => a.localeCompare(b))),
    ),
  });
}

export function renderReport(report: CorpusRunReport, reporter: CorpusReporter): string {
  if (reporter === "json") return `${JSON.stringify(report)}\n`;
  if (reporter === "junit") return renderJunit(report);
  const lines = [
    `corpus hash: ${report.corpusHash}`,
    `cases: ${report.totals.total}; passed: ${report.totals.passed}; failed: ${report.totals.failed}`,
    ...report.cases.map(
      (item) =>
        `${item.status.toUpperCase()} ${item.id}${item.reasons.length === 0 ? "" : ` (${item.reasons.join(",")})`}`,
    ),
  ];
  return `${lines.join("\n")}\n`;
}

function renderJunit(report: CorpusRunReport): string {
  const cases = report.cases
    .map((item) => {
      const name = xml(item.id);
      if (item.status === "passed")
        return `<testcase name="${name}" time="${item.durationMs / 1_000}"/>`;
      return `<testcase name="${name}" time="${item.durationMs / 1_000}"><failure message="${xml(item.reasons.join(","))}"/></testcase>`;
    })
    .join("");
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="openagentfence-corpus" tests="${report.totals.total}" failures="${report.totals.failed}" corpusHash="${report.corpusHash}">${cases}</testsuite>\n`;
}

function xml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function sanitizeReasons(status: CorpusCaseStatus, reasons: readonly string[]): readonly string[] {
  const safe = [...new Set(reasons.filter((reason) => REPORT_REASON_CODES.has(reason)))].sort();
  return Object.freeze(safe.length === 0 && status === "failed" ? ["corpus_case_failed"] : safe);
}

function isDeterministicControl(item: CorpusCase): boolean {
  // Explicit approval denies by default and is a deterministic Action Guard
  // control; semantic, observed-only, and unavailable entries never satisfy
  // INV-02 coverage on their own.
  return item.expected.control === "deterministic" || item.expected.control === "approval";
}

function boundedDuration(value: number): number {
  return Number.isFinite(value) && value >= 0 && value <= 60 * 60 * 1_000 ? Math.floor(value) : 0;
}
