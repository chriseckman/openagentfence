import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  validateCorpusCase,
  loadCorpusDocument,
  loadCorpusFile,
  corpusHash,
  CORPUS_SCHEMA_VERSION,
} from "../src/index.js";
import type { CorpusCase } from "../src/index.js";

function validCase(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "c1",
    mode: "attack",
    attackClasses: ["A3"],
    invariants: ["INV-01"],
    kind: "static",
    pages: [{ url: "/hidden-dom/display-none-instruction.html" }],
    task: "Find a hotel",
    expected: { outcome: "BLOCK", reasons: ["destination_not_allowed"] },
    ...overrides,
  };
}

describe("corpus-case validation (OAF-TEST-002)", () => {
  it("accepts a valid case", () => {
    expect(validateCorpusCase(validCase())).not.toBeNull();
  });

  it("rejects unknown fields, modes, kinds, and executable metadata", () => {
    expect(validateCorpusCase(validCase({ bogus: true }))).toBeNull();
    expect(validateCorpusCase(validCase({ mode: "neutral" }))).toBeNull();
    expect(validateCorpusCase(validCase({ kind: "generated" }))).toBeNull();
    expect(validateCorpusCase(validCase({ generator: "eval(...)" }))).toBeNull();
    expect(validateCorpusCase(validCase({ grantCapabilities: ["uploads"] }))).toBeNull();
    expect(validateCorpusCase(validCase({ policy: { exec: "x" } }))).toBeNull();
  });

  it("rejects malformed pages, expected, and oversized strings", () => {
    expect(validateCorpusCase(validCase({ pages: [{ url: 42 }] }))).toBeNull();
    expect(validateCorpusCase(validCase({ expected: {} }))).toBeNull();
    expect(validateCorpusCase(validCase({ task: "x".repeat(100_000) }))).toBeNull();
  });

  it("never throws on hostile inputs", () => {
    const hostile = [
      null,
      undefined,
      42,
      "x",
      [],
      [1, 2],
      { id: { $ref: "x" } },
      { id: "c", mode: "attack" },
    ];
    for (const value of hostile) {
      expect(() => validateCorpusCase(value)).not.toThrow();
    }
  });
});

describe("corpus document loading", () => {
  it("loads the seed corpus with a stable hash", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
    const loaded = loadCorpusFile(join(root, "security-corpus", "corpus.json"));
    expect(loaded.schemaVersion).toBe(CORPUS_SCHEMA_VERSION);
    expect(loaded.cases.length).toBe(9);
    expect(loaded.hash).toBe(corpusHash(loaded.cases));
    expect(loaded.cases.map((c) => c.id)).toContain("hidden-dom-display-none-instruction");
    expect(loaded.cases.map((c) => c.id)).toContain("aria-accessibility-only-instruction");
    expect(loaded.cases.map((c) => c.id)).toContain("hidden-dom-benign-skip-link");
    expect(loaded.cases.map((c) => c.id)).toContain("navigation-private-network-link");
    expect(loaded.cases.map((c) => c.id)).toContain("navigation-cross-origin-link");
    expect(loaded.cases.map((c) => c.id)).toContain("navigation-benign-same-site-link");
  });

  it("rejects malformed, wrong-version, and unknown-field documents", () => {
    expect(() => loadCorpusDocument("not json")).toThrow();
    expect(() => loadCorpusDocument('{ "schemaVersion": "9.9.9", "cases": [] }')).toThrow();
    expect(() =>
      loadCorpusDocument(
        JSON.stringify({ schemaVersion: "1.0.0", cases: [validCase({ extra: true })] }),
      ),
    ).toThrow();
  });

  it("rejects documents over the case count bound", () => {
    const many = Array.from({ length: 10_001 }, (_, i) => validCase({ id: `c${i}` }));
    expect(() =>
      loadCorpusDocument(JSON.stringify({ schemaVersion: "1.0.0", cases: many })),
    ).toThrow();
  });
});

describe("corpus hash determinism", () => {
  it("is deterministic for identical input and content-sensitive", () => {
    const a = [validateCorpusCase(validCase()), validateCorpusCase(validCase({ id: "c2" }))];
    const b = [validateCorpusCase(validCase()), validateCorpusCase(validCase({ id: "c2" }))];
    const c = [validateCorpusCase(validCase({ task: "different" }))];
    expect(corpusHash(a as CorpusCase[])).toBe(corpusHash(b as CorpusCase[]));
    expect(corpusHash(a as CorpusCase[])).not.toBe(corpusHash(c as CorpusCase[]));
  });

  it("has no raw synthetic secrets in serialized seed corpus", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
    const raw = readFileSync(join(root, "security-corpus", "corpus.json"), "utf8");
    expect(raw).not.toMatch(/sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-/);
  });
});
