import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CORPUS_SCHEMA_VERSION,
  corpusHash,
  corpusVitestCases,
  loadCorpusDocument,
  loadCorpusFile,
  runCorpusCases,
  validateCorpusCase,
} from "../src/index.js";
import type { CorpusCase } from "../src/index.js";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const corpusRoot = join(repositoryRoot, "security-corpus");

function validCase(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "c1",
    mode: "attack",
    attackClasses: ["A3"],
    invariants: ["INV-01"],
    kind: "static",
    surfaces: ["hidden-dom"],
    initiator: "none",
    pages: [{ url: "/hidden-dom/display-none-instruction.html" }],
    task: "Find a hotel",
    expected: { outcome: "BLOCK", reasons: ["destination_not_allowed"] },
    ...overrides,
  };
}

function document(cases: readonly unknown[]): string {
  return JSON.stringify({ schemaVersion: CORPUS_SCHEMA_VERSION, cases });
}

describe("corpus-case validation (OAF-TEST-002)", () => {
  it("accepts a closed static case and inert bounded adaptive metadata", () => {
    expect(validateCorpusCase(validCase())).not.toBeNull();
    expect(
      validateCorpusCase(
        validCase({
          kind: "adaptive-ready",
          adaptive: { seed: "seed", transformations: ["whitespace"], maxVariants: 8 },
        }),
      ),
    ).not.toBeNull();
  });

  it("rejects unknown, invalid, executable, or authority-changing generator metadata", () => {
    expect(validateCorpusCase(validCase({ bogus: true }))).toBeNull();
    expect(validateCorpusCase(validCase({ mode: "neutral" }))).toBeNull();
    expect(validateCorpusCase(validCase({ kind: "generated" }))).toBeNull();
    expect(validateCorpusCase(validCase({ generator: "eval(...)" }))).toBeNull();
    expect(validateCorpusCase(validCase({ grantCapabilities: ["uploads"] }))).toBeNull();
    expect(
      validateCorpusCase(
        validCase({
          kind: "adaptive-ready",
          adaptive: {
            seed: "x",
            transformations: ["whitespace"],
            maxVariants: 2,
            policy: { effect: "ALLOW" },
          },
        }),
      ),
    ).toBeNull();
    expect(validateCorpusCase(validCase({ policy: { exec: "x" } }))).toBeNull();
  });

  it("rejects malformed and unbounded fields, vocabularies, and kind metadata", () => {
    expect(validateCorpusCase(validCase({ pages: [{ url: 42 }] }))).toBeNull();
    expect(validateCorpusCase(validCase({ expected: {} }))).toBeNull();
    expect(validateCorpusCase(validCase({ task: "x".repeat(100_000) }))).toBeNull();
    expect(validateCorpusCase(validCase({ attackClasses: ["A99"] }))).toBeNull();
    expect(validateCorpusCase(validCase({ invariants: ["INV-99"] }))).toBeNull();
    expect(validateCorpusCase(validCase({ surfaces: ["browser-magic"] }))).toBeNull();
    expect(validateCorpusCase(validCase({ initiator: "provider" }))).toBeNull();
    expect(validateCorpusCase(validCase({ kind: "adaptive-ready" }))).toBeNull();
    expect(validateCorpusCase(validCase({ adaptive: { seed: "x" } }))).toBeNull();
  });

  it("never invokes accessors or throws on hostile inputs", () => {
    const accessor = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(accessor, "id", {
      enumerable: true,
      get: () => {
        throw new Error("must not run");
      },
    });
    const hostile = [null, undefined, 42, "x", [], [1, 2], accessor, { id: { $ref: "x" } }];
    for (const value of hostile) expect(() => validateCorpusCase(value)).not.toThrow();
  });
});

describe("corpus document loading", () => {
  it("loads all seed cases, resolves every fixture, and includes file content in its hash", () => {
    const loaded = loadCorpusFile(join(corpusRoot, "corpus.json"));
    expect(loaded.schemaVersion).toBe(CORPUS_SCHEMA_VERSION);
    expect(loaded.cases).toHaveLength(227);
    expect(Object.keys(loaded.fixtureHashes)).toHaveLength(31);
    expect(loaded.hash).toBe(corpusHash(loaded.cases, loaded.fixtureHashes));
    expect(loaded.cases.map((item) => item.id)).toContain("byok-guard-malformed-output");
    expect(loaded.fixtureHashes["/guard-failure/malformed.html"]).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("rejects malformed, stale-version, unknown-field, duplicate, and empty documents", () => {
    expect(() => loadCorpusDocument("not json")).toThrow();
    expect(() => loadCorpusDocument('{ "schemaVersion": "9.9.9", "cases": [] }')).toThrow();
    expect(() =>
      loadCorpusDocument(
        JSON.stringify({ schemaVersion: CORPUS_SCHEMA_VERSION, cases: [], extra: 1 }),
      ),
    ).toThrow();
    expect(() => loadCorpusDocument(document([validCase(), validCase()]))).toThrow();
    expect(() => loadCorpusDocument(document([]))).toThrow();
  });

  it("rejects documents over the bounded case count", () => {
    const many = Array.from({ length: 4_097 }, (_, index) => validCase({ id: `c${index}` }));
    expect(() => loadCorpusDocument(document(many))).toThrow();
  });
});

describe("corpus hashing and runner seams", () => {
  it("is order-independent, content-sensitive, and fixture-sensitive", () => {
    const first = validateCorpusCase(validCase());
    const second = validateCorpusCase(validCase({ id: "c2" }));
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    const forward = [first, second] as CorpusCase[];
    const reverse = [second, first] as CorpusCase[];
    expect(corpusHash(forward)).toBe(corpusHash(reverse));
    expect(corpusHash(forward, { "/a.html": "one" })).not.toBe(
      corpusHash(forward, { "/a.html": "two" }),
    );
  });

  it("exposes deterministic Vitest tuples and executes every selected case once", async () => {
    const loaded = loadCorpusFile(join(corpusRoot, "corpus.json"));
    const selected = corpusVitestCases(loaded, (item) => item.mode === "benign");
    expect(selected.map(([id]) => id)).toEqual([...selected.map(([id]) => id)].sort());
    const visited: string[] = [];
    const results = await runCorpusCases(loaded, (item) => {
      visited.push(item.id);
      return item.expected.outcome;
    });
    expect(results).toHaveLength(loaded.cases.length);
    expect(visited).toEqual(loaded.cases.map((item) => item.id));
  });
});

describe("corpus fixture hygiene", () => {
  it("contains no credential-shaped raw values anywhere in the corpus tree", () => {
    for (const path of allFiles(corpusRoot)) {
      const raw = readFileSync(path, "utf8");
      expect(raw, path).not.toMatch(
        /(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/u,
      );
    }
  });
});

function allFiles(root: string): readonly string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = join(root, entry.name);
    return entry.isDirectory() ? allFiles(path) : [path];
  });
}
