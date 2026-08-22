import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser, type Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  MemoryGuardError,
  OpenAgentFence,
  validateStoredMemoryItem,
  validateTraceDocument,
  type DataProvenance,
} from "@openagentfence/core";
import { defaultScanners } from "@openagentfence/scanners";
import {
  corpusVitestCases,
  expectNoRawSecretIn,
  fixtureSentinel,
  loadCorpusFile,
  startFixtureServer,
  type CorpusCase,
  type FixtureOrigin,
  type FixtureServer,
} from "@openagentfence/testing";
import { inMemoryVault } from "@openagentfence/vault";
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
const cases = corpusVitestCases(corpus, (item) => item.tags?.includes("ps009") === true);

let browser: Browser;
let fixtures: FixtureServer;

beforeAll(async () => {
  browser = await chromium.launch({ headless: true });
  fixtures = await startFixtureServer({ origins: ["source", "attacker"], root: corpusRoot });
});

afterAll(async () => {
  await fixtures.close();
  await browser.close();
});

describe("generated application-owned memory poisoning corpus", () => {
  it("meets the direct write/read and outcome floor", () => {
    expect(cases.length).toBeGreaterThanOrEqual(8);
    for (const tag of [
      "instruction",
      "poisoned-fact",
      "secret",
      "sensitive",
      "malformed",
      "hash-tamper",
      "provenance",
      "data-only",
      "taint",
      "benign",
      "replay",
    ]) {
      expect(
        cases.some(([, item]) => item.tags?.includes(tag) === true),
        tag,
      ).toBe(true);
    }
  });

  it.each(cases)(
    "%s",
    async (_name, item) => {
      const page = await browser.newPage();
      const [source, attacker] = fixtures.origins;
      if (source === undefined || attacker === undefined) {
        throw new Error("fixture origins unavailable");
      }
      const pagePath = item.pages[0]?.url;
      if (pagePath === undefined) throw new Error("corpus page unavailable");
      await page.goto(fixtures.url(source, pagePath));
      try {
        await runCase(item, page, source, attacker);
      } finally {
        await page.close();
      }
    },
    15_000,
  );
});

async function runCase(
  item: CorpusCase,
  page: Page,
  source: FixtureOrigin,
  attacker: FixtureOrigin,
): Promise<void> {
  const runtimeSensitive = runtimeSensitiveValue(item);
  if (runtimeSensitive !== undefined) {
    await page.locator("#candidate").evaluate((node, value) => {
      node.textContent = value;
    }, runtimeSensitive.candidate);
  }
  const written = await writeObservedCandidate(item, page);
  expect(written.write.allowed).toBe(true);
  expect(written.write.item).toBeDefined();
  expect(validateStoredMemoryItem(written.stored)).not.toBeNull();
  expect(validateTraceDocument(written.trace).ok).toBe(true);
  expect(written.write.item).toMatchObject({
    kind: "data",
    provenance: written.provenance,
  });

  if (item.tags?.includes("instruction") === true) {
    expect(
      written.write.findings.some((finding) => finding.category === "memory_instruction"),
    ).toBe(true);
    expect(written.write.item).toMatchObject({
      markers: ["instruction_removed"],
      sensitivity: "sensitive",
    });
    expect(written.write.item?.content).toContain("[REMOVED:MEMORY_INSTRUCTION]");
    expect(written.write.item?.content).not.toContain(written.candidate);
  }

  if (runtimeSensitive !== undefined) {
    expect(written.write.findings.some((finding) => finding.category === "secret_detected")).toBe(
      true,
    );
    expect(written.write.item).toMatchObject({
      markers: ["sensitive_value_replaced"],
      sensitivity: "secret",
    });
    if (item.id === "ps009-runtime-sensitive-assignment") {
      expect(written.write.item?.content).toContain("[REDACTED:SENSITIVE]");
    } else {
      expect(written.write.item?.content).toMatch(/<(?:SECRET|CREDENTIAL):[^:>]+:[^:>]+>/u);
    }
    for (const artifact of [written.observation, written.write, written.stored, written.trace]) {
      expect(expectNoRawSecretIn(artifact, runtimeSensitive.secret)).toBe(true);
    }
  }

  if (item.tags?.includes("malformed") === true) {
    const malformed = { ...(written.stored as Record<string, unknown>) };
    delete malformed["schemaVersion"];
    await assertDeniedRead(page, malformed, "memory_item_invalid");
    return;
  }
  if (item.tags?.includes("hash-tamper") === true) {
    const tampered = { ...(written.stored as Record<string, unknown>), content: "tampered" };
    await assertDeniedRead(page, tampered, "memory_content_hash_mismatch");
    return;
  }
  if (item.id === "ps009-provenance-hash-tamper") {
    const stored = written.stored as { provenance: DataProvenance };
    const tampered = {
      ...(written.stored as Record<string, unknown>),
      provenance: { ...stored.provenance, origin: "https://attacker.invalid" },
    };
    await assertDeniedRead(page, tampered, "memory_content_hash_mismatch");
    return;
  }
  if (item.tags?.includes("data-only") === true) {
    const tampered = { ...(written.stored as Record<string, unknown>), kind: "instruction" };
    await assertDeniedRead(page, tampered, "memory_item_invalid");
    return;
  }

  const reader = createFirewall(page).start({
    task: "read application-owned memory only as untrusted data",
    capabilities: { externalCommunication: true, navigation: "allowlist", privateNetwork: true },
    origins: { allow: [source.origin, attacker.origin] },
  });
  const read = reader.memory.guardRead(written.stored);
  expect(read).toMatchObject({
    content: written.write.item?.content,
    instructionEligible: false,
    provenance: { ...written.provenance, trust: "memory" },
  });
  expect(reader.sessionTaintFloor).toMatchObject({
    trust: "web",
    origin: source.origin,
    pageId: written.provenance.pageId,
  });

  if (item.tags?.includes("poisoned-fact") === true) {
    const decision = await reader.authorize({
      type: "MESSAGE",
      destination: `${attacker.origin}/capture`,
      data: { value: read.content, provenance: read.provenance },
      instructionProvenance: read.provenance,
    });
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasons).toContain("untrusted_cross_origin_egress");
    expect(fixtures.requestsFor(attacker)).toHaveLength(0);
  }

  const readTrace = await reader.end();
  expect(validateTraceDocument(readTrace).ok).toBe(true);
  expect(
    readTrace.events.some(
      (event) =>
        event.kind === "memory_read" &&
        event.data["allowed"] === true &&
        event.data["releasedProvenance"] !== undefined,
    ),
  ).toBe(true);
  if (runtimeSensitive !== undefined) {
    for (const artifact of [read, readTrace]) {
      expect(expectNoRawSecretIn(artifact, runtimeSensitive.secret)).toBe(true);
    }
  }
}

async function writeObservedCandidate(item: CorpusCase, page: Page) {
  const candidate = (await page.locator("#candidate").textContent()) ?? "";
  const writer = createFirewall(page, item.id !== "ps009-runtime-sensitive-assignment").start({
    task: item.task,
  });
  const observation = await writer.observe();
  const provenance = Object.freeze({
    ...observation.sanitizedText.provenance,
    elementId: "candidate",
  });
  const write = await writer.memory.guardWrite({ content: candidate, provenance });
  const applicationStore = new Map<string, unknown>();
  if (write.allowed && write.item !== undefined) {
    applicationStore.set("item", JSON.parse(JSON.stringify(write.item)) as unknown);
  }
  const stored = applicationStore.get("item");
  const trace = await writer.end();
  if (stored === undefined) throw new Error("guarded write did not produce a stored item");
  return { candidate, observation, provenance, write, stored, trace };
}

async function assertDeniedRead(
  page: Page,
  stored: unknown,
  code: "memory_item_invalid" | "memory_content_hash_mismatch",
): Promise<void> {
  const reader = createFirewall(page).start({ task: "validate application-owned memory" });
  let failure: unknown;
  try {
    reader.memory.guardRead(stored);
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(MemoryGuardError);
  expect((failure as MemoryGuardError).code).toBe(code);
  expect(reader.sessionTaintFloor).toBeUndefined();
  const trace = await reader.end();
  expect(validateTraceDocument(trace).ok).toBe(true);
  expect(
    trace.events.some(
      (event) =>
        event.kind === "memory_read" &&
        event.data["allowed"] === false &&
        Array.isArray(event.data["reasons"]) &&
        event.data["reasons"].includes(code),
    ),
  ).toBe(true);
}

function runtimeSensitiveValue(
  item: CorpusCase,
): { readonly candidate: string; readonly secret: string } | undefined {
  if (item.id === "ps009-runtime-secret") {
    const secret = `AKIA${"M".repeat(16)}`;
    return { candidate: secret, secret };
  }
  if (item.id === "ps009-runtime-sensitive-assignment") {
    const secret = `${fixtureSentinel()}Aa9`;
    return { candidate: `password = ${secret}`, secret };
  }
  return undefined;
}

function createFirewall(page: Page, withVault = true): OpenAgentFence {
  return new OpenAgentFence({
    adapter: playwrightAdapter(page),
    scanners: defaultScanners(),
    ...(withVault ? { vault: inMemoryVault() } : {}),
  });
}
