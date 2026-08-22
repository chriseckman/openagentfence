import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OpenAgentFence, validateTraceDocument } from "@openagentfence/core";
import { defaultScanners } from "@openagentfence/scanners";
import {
  corpusVitestCases,
  loadCorpusFile,
  startFixtureServer,
  type FixtureServer,
} from "@openagentfence/testing";
import { playwrightAdapter } from "../../src/index.js";

const corpusRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "..",
  "security-corpus",
);
const corpus = loadCorpusFile(join(corpusRoot, "corpus.json"));
const cases = corpusVitestCases(corpus, (item) => item.tags?.includes("ps010") === true);

let browser: Browser;
let fixtures: FixtureServer;

beforeAll(async () => {
  browser = await chromium.launch({ headless: true });
  fixtures = await startFixtureServer({ origins: ["source", "sink"], root: corpusRoot });
});

afterAll(async () => {
  await fixtures.close();
  await browser.close();
});

describe("generated multilingual and realistic benign corpus", () => {
  it("meets the multilingual, script, RTL, and benign-category floors", () => {
    const attacks = cases.filter(([, item]) => item.mode === "attack");
    const benign = cases.filter(([, item]) => item.mode === "benign");
    const scripts = new Set(
      attacks.flatMap(([, item]) => (item.tags ?? []).filter((tag) => tag.startsWith("script-"))),
    );

    expect(attacks).toHaveLength(12);
    expect(benign).toHaveLength(30);
    expect(scripts.size).toBeGreaterThanOrEqual(3);
    expect(attacks.some(([, item]) => item.tags?.includes("rtl") === true)).toBe(true);
    for (const category of ["news", "shop", "docs", "forms", "dashboard", "hidden-ui"]) {
      expect(benign.filter(([, item]) => item.tags?.includes(category) === true)).toHaveLength(5);
    }
  });

  it.each(cases)(
    "%s",
    async (_name, item) => {
      const page = await browser.newPage();
      const source = fixtures.origins[0];
      const pagePath = item.pages[0]?.url;
      if (source === undefined || pagePath === undefined) {
        throw new Error("PS-010 fixture input unavailable");
      }

      try {
        await page.goto(fixtures.url(source, pagePath));
        const session = new OpenAgentFence({
          adapter: playwrightAdapter(page),
          scanners: defaultScanners(),
        }).start({ task: item.task });
        const result = await session.observe();

        for (const category of item.expected.findings ?? []) {
          const finding = result.findings.find((candidate) => candidate.category === category);
          expect(
            finding,
            `${item.id} missing ${category}; observed ${result.findings
              .map((candidate) => candidate.category)
              .join(", ")}`,
          ).toBeDefined();
          expect(finding?.provenance).toMatchObject({
            trust: "web",
            origin: source.origin,
          });
          expect(finding?.provenance.pageId).toBeDefined();
        }

        if (item.mode === "benign") {
          const authoritativeFindings = result.findings.filter(
            (finding) =>
              finding.recommendedAction === "block" || finding.recommendedAction === "approve",
          );
          expect(authoritativeFindings).toEqual([]);
          expect(["ALLOW", "ALLOW_SANITIZED"]).toContain(result.assessment.verdict);
          expect(session.riskState).toBe("NORMAL");
          expect(session.riskScore).toBe(0);
        } else {
          expect(result.assessment.verdict).toBe(item.expected.outcome);
          expect(session.riskState).toBe(item.expected.risk ?? "NORMAL");
        }

        const trace = await session.end();
        expect(validateTraceDocument(trace).ok).toBe(true);
        if (item.mode === "benign") {
          expect(trace.events.some((event) => event.kind === "risk_change")).toBe(false);
        }
      } finally {
        await page.close();
      }
    },
    15_000,
  );
});
