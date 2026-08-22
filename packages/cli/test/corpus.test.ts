import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CORPUS_EXIT,
  CorpusRuntimeUnavailableError,
  runCorpusCommand,
  type CorpusCommandDependencies,
} from "../src/commands/corpus.js";

const workspaces: string[] = [];

afterEach(async () => {
  await Promise.all(workspaces.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("openagentfence test --corpus", () => {
  it("renders deterministic JSON, JUnit, class filters, and a stable corpus hash", async () => {
    const corpus = await tinyCorpus();
    const stdout: string[] = [];
    const exit = await runCorpusCommand(
      ["--corpus", corpus, "--filter", "class=A1", "--reporter", "json"],
      { stdout: (text) => stdout.push(text), stderr: () => undefined, now: sequenceClock() },
      passingExecutor(),
    );
    expect(exit).toBe(CORPUS_EXIT.success);
    const report = JSON.parse(stdout.join("")) as {
      corpusHash: string;
      selectedClasses: string[];
      totals: { total: number; failed: number };
      cases: Array<{ id: string; durationMs: number }>;
    };
    expect(report.corpusHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(report.selectedClasses).toEqual(["A1"]);
    expect(report.totals).toEqual({ total: 1, passed: 1, failed: 0 });
    expect(report.cases).toEqual([
      { id: "tiny-attack", status: "passed", reasons: [], durationMs: 1 },
    ]);

    const junit: string[] = [];
    const junitExit = await runCorpusCommand(
      ["--corpus", corpus, "--filter", "class=A1", "--reporter", "junit"],
      { stdout: (text) => junit.push(text), stderr: () => undefined },
      passingExecutor(),
    );
    expect(junitExit).toBe(CORPUS_EXIT.success);
    expect(junit.join("")).toContain('<testsuite name="openagentfence-corpus"');
  });

  it("turns a deliberately weakened isolated executor into a red gate without reporting its raw sentinel", async () => {
    const corpus = await tinyCorpus();
    const stdout: string[] = [];
    const secret = "oaf_runtime_sentinel_should_not_escape";
    const exit = await runCorpusCommand(
      ["--corpus", corpus, "--filter", "class=A1", "--reporter", "json"],
      { stdout: (text) => stdout.push(text), stderr: () => undefined },
      {
        createExecutor: async () => ({
          execute: async () => ({ status: "failed" as const, reasons: [secret] }),
        }),
      },
    );
    expect(exit).toBe(CORPUS_EXIT.regression);
    expect(stdout.join("")).not.toContain(secret);
    expect(stdout.join("")).toContain("corpus_case_failed");
  });

  it("rejects automatic snapshot updates and malformed filters with usage exit status", async () => {
    const corpus = await tinyCorpus();
    const errors: string[] = [];
    await expect(
      runCorpusCommand(
        ["--corpus", corpus, "--update-snapshots"],
        { stdout: () => undefined, stderr: (text) => errors.push(text), ci: true },
        passingExecutor(),
      ),
    ).resolves.toBe(CORPUS_EXIT.usage);
    await expect(
      runCorpusCommand(
        ["--corpus", corpus, "--filter", "class=A99"],
        { stdout: () => undefined, stderr: (text) => errors.push(text) },
        passingExecutor(),
      ),
    ).resolves.toBe(CORPUS_EXIT.usage);
    expect(errors.join("")).toContain("usage:");
  });

  it("returns a value-free unavailable result when the local browser peer is absent", async () => {
    const corpus = await tinyCorpus();
    const errors: string[] = [];
    const exit = await runCorpusCommand(
      ["--corpus", corpus, "--filter", "class=A1"],
      { stdout: () => undefined, stderr: (text) => errors.push(text) },
      {
        createExecutor: async () => {
          throw new CorpusRuntimeUnavailableError();
        },
      },
    );
    expect(exit).toBe(CORPUS_EXIT.usage);
    expect(errors).toEqual(["corpus runtime unavailable\n"]);
  });
});

function passingExecutor(): CorpusCommandDependencies {
  return {
    createExecutor: async () => ({
      execute: async () => ({ status: "passed" as const, reasons: [] }),
    }),
  };
}

function sequenceClock(): () => number {
  let value = 0;
  return () => value++;
}

async function tinyCorpus(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "openagentfence-cli-corpus-"));
  workspaces.push(directory);
  await writeFile(join(directory, "fixture.txt"), "synthetic fixture", "utf8");
  await writeFile(
    join(directory, "corpus.json"),
    JSON.stringify({
      schemaVersion: "1.1.0",
      cases: [
        {
          id: "tiny-attack",
          mode: "attack",
          attackClasses: ["A1"],
          invariants: ["INV-01"],
          kind: "static",
          surfaces: ["dom"],
          initiator: "none",
          pages: [{ url: "/fixture.txt" }],
          task: "test the isolated corpus executor",
          expected: { outcome: "BLOCK", control: "deterministic" },
        },
      ],
    }),
    "utf8",
  );
  return directory;
}
