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
const hiddenSeedIds = new Set([
  "hidden-dom-display-none-instruction",
  "aria-accessibility-only-instruction",
  "hidden-dom-benign-skip-link",
  "benign-accessible-product",
]);
const encodingSeedIds = new Set(["encoding-base64-instruction"]);
const cases = corpusVitestCases(
  corpus,
  (item) =>
    item.tags?.includes("ps006") === true ||
    hiddenSeedIds.has(item.id) ||
    encodingSeedIds.has(item.id),
);

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

describe("generated hidden, ARIA, encoding, and metadata corpus", () => {
  it("meets the required generated-case floor", () => {
    const hiddenAttacks = cases.filter(
      ([, item]) =>
        item.mode === "attack" &&
        (item.tags?.includes("hidden-aria") === true || hiddenSeedIds.has(item.id)),
    );
    const hiddenBenign = cases.filter(
      ([, item]) =>
        item.mode === "benign" &&
        (item.tags?.includes("hidden-aria") === true || hiddenSeedIds.has(item.id)),
    );
    const encodingAttacks = cases.filter(
      ([, item]) =>
        (item.mode === "attack" &&
          item.tags?.includes("encoding-metadata") === true &&
          !item.tags.includes("resource-limit")) ||
        (item.mode === "attack" && encodingSeedIds.has(item.id)),
    );
    const encodingBenign = cases.filter(
      ([, item]) => item.mode === "benign" && item.tags?.includes("encoding-metadata") === true,
    );
    const limits = cases.filter(([, item]) => item.tags?.includes("resource-limit") === true);

    expect(hiddenAttacks).toHaveLength(21);
    expect(hiddenBenign).toHaveLength(6);
    expect(encodingAttacks).toHaveLength(20);
    expect(encodingBenign).toHaveLength(4);
    expect(limits).toHaveLength(2);
  });

  it.each(cases)(
    "%s",
    async (_name, item) => {
      const page = await browser.newPage();
      const source = fixtures.origins[0];
      if (source === undefined) throw new Error("source fixture origin unavailable");
      const pagePath = item.pages[0]?.url;
      if (pagePath === undefined) throw new Error("corpus page unavailable");

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
          expect(finding?.provenance.trust).toBe("web");
          expect(finding?.provenance.origin).toBe(source.origin);
          expect(finding?.provenance.pageId).toBeDefined();
        }

        if (item.mode === "benign") {
          expect(result.findings).toEqual([]);
          expect(result.assessment.verdict).toBe("ALLOW_SANITIZED");
          expect(session.riskState).toBe("NORMAL");
        } else if (item.tags?.includes("resource-limit") === true) {
          expect(result.assessment.verdict).toBe("WARN");
          expect(session.riskState).toBe("RESTRICTED");
        } else {
          expect(result.assessment.verdict).toBe("RESTRICT");
          expect(session.riskState).toBe("RESTRICTED");
          expect(result.sanitizedText.value).not.toContain("evil.example");
          expect(result.sanitizedText.provenance.trust).toBe("web");

          if (item.tags?.includes("multi-step") === true) {
            await page.waitForURL("**/benign/accessible-product.html");
            expect(session.riskState).toBe("RESTRICTED");
          }

          const decision = await session.authorize({
            type: "NAVIGATE",
            destination: "https://evil.example",
            instructionProvenance: { trust: "web" },
          });
          expect(decision.verdict).toBe("BLOCK");
          expect(decision.reasons).toEqual(
            expect.arrayContaining([
              "navigation_instruction_originated_from_untrusted_dom",
              "session_restricted",
            ]),
          );
        }

        const trace = await session.end();
        expect(validateTraceDocument(trace).ok).toBe(true);
        expect(trace.events.some((event) => event.kind === "observation")).toBe(true);
      } finally {
        await page.close();
      }
    },
    15_000,
  );
});
