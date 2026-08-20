import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { OpenAgentFence, validateTraceDocument } from "@openagentfence/core";
import { defaultScanners } from "@openagentfence/scanners";
import {
  expectNoRawSecretIn,
  fixtureSentinel,
  loadCorpusFile,
  startFixtureServer,
  type FixtureServer,
} from "@openagentfence/testing";
import { playwrightAdapter } from "../../src/index.js";
import type { Browser } from "playwright";

let browser: Browser;
let fixtures: FixtureServer | undefined;

const corpus = loadCorpusFile(
  fileURLToPath(new URL("../../../../security-corpus/corpus.json", import.meta.url)),
);
const attackCase = corpus.cases.find((item) => item.id === "hidden-dom-display-none-instruction");
const benignCase = corpus.cases.find((item) => item.id === "hidden-dom-benign-skip-link");
if (attackCase === undefined || benignCase === undefined)
  throw new Error("vertical-slice corpus cases missing");

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser.close();
});

afterEach(async () => {
  await fixtures?.close();
  fixtures = undefined;
});

describe("vertical slice: versioned hidden-DOM corpus (OAF-BROWSER-012)", () => {
  it("contains the attack through the local fixture server with an ordered redacted trace", async () => {
    fixtures = await startFixtureServer();
    const page = await browser.newPage();
    const origin = fixtures.origins[0];
    if (origin === undefined) throw new Error("fixture origin missing");
    await page.goto(`${origin.origin}${attackCase.pages[0]?.url ?? ""}`);
    const firewall = new OpenAgentFence({
      adapter: playwrightAdapter(page),
      scanners: defaultScanners(),
    });
    const session = firewall.start({ task: attackCase.task });
    const sentinel = fixtureSentinel();

    const result = await session.observe();
    expect(result.findings.some((finding) => finding.category === "hidden_dom_instruction")).toBe(
      true,
    );
    expect(result.findings.every((finding) => finding.provenance.trust === "web")).toBe(true);
    expect(result.assessment.verdict).toBe("RESTRICT");
    expect(session.riskState).toBe("RESTRICTED");
    expect(result.sanitizedText.value).not.toContain("evil.example");
    expect(result.sanitizedText.provenance.trust).toBe("web");

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

    const trace = await session.end();
    expect(validateTraceDocument(trace).ok).toBe(true);
    expect(trace.events[0]?.kind).toBe("session_start");
    expect(trace.events.at(-1)?.kind).toBe("session_end");
    expect(trace.events.some((event) => event.kind === "finding")).toBe(true);
    expect(trace.events.some((event) => event.kind === "taint_activation")).toBe(true);
    expect(expectNoRawSecretIn(trace, sentinel)).toBe(true);
    await writeSafeTraceArtifact(trace);
    expect(corpus.hash).toMatch(/^[0-9a-f]{64}$/);
    await page.close();
  });

  it("allows the benign corpus sibling without findings or state change", async () => {
    fixtures = await startFixtureServer();
    const page = await browser.newPage();
    const origin = fixtures.origins[0];
    if (origin === undefined) throw new Error("fixture origin missing");
    await page.goto(`${origin.origin}${benignCase.pages[0]?.url ?? ""}`);
    const firewall = new OpenAgentFence({
      adapter: playwrightAdapter(page),
      scanners: defaultScanners(),
    });
    const session = firewall.start({ task: benignCase.task });

    const result = await session.observe();
    expect(result.findings).toEqual([]);
    expect(result.assessment.verdict).toBe("ALLOW_SANITIZED");
    expect(session.riskState).toBe("NORMAL");
    expect(validateTraceDocument(await session.end()).ok).toBe(true);
    await page.close();
  });
});

async function writeSafeTraceArtifact(trace: unknown): Promise<void> {
  const directory = process.env["OAF_TRACE_ARTIFACT_DIR"];
  if (directory === undefined || directory.length === 0) return;
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, "hidden-dom-attack.redacted-trace.json"),
    `${JSON.stringify(trace, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
}
