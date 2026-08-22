import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser, type Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  OpenAgentFence,
  compileTaskContract,
  evaluateDestination,
  evaluateRedirectChain,
  provenanced,
  secureDefaultPolicyEngine,
  validateTaskContract,
  validateTraceDocument,
  type CanonicalAction,
  type PolicyEngine,
  type TaskContract,
} from "@openagentfence/core";
import {
  corpusVitestCases,
  loadCorpusFile,
  startFixtureServer,
  type CorpusCase,
  type FixtureOrigin,
  type FixtureServer,
} from "@openagentfence/testing";
import { playwrightAdapter, wrapPage } from "../../src/index.js";

const corpusRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "..",
  "security-corpus",
);
const corpus = loadCorpusFile(join(corpusRoot, "corpus.json"));
const cases = corpusVitestCases(corpus, (item) => item.tags?.includes("ps007") === true);

const SSRF_DESTINATIONS: Readonly<Record<string, string>> = Object.freeze({
  "ps007-ssrf-localhost": "http://localhost:9200/",
  "ps007-ssrf-loopback": "http://127.0.0.1:9200/",
  "ps007-ssrf-decimal-ip": "http://2130706433:9200/",
  "ps007-ssrf-hex-ip": "http://0x7f000001:9200/",
  "ps007-ssrf-rfc1918-10": "http://10.0.0.5/",
  "ps007-ssrf-rfc1918-172": "http://172.16.0.5/",
  "ps007-ssrf-rfc1918-192": "http://192.168.1.5/",
  "ps007-ssrf-link-local": "http://169.254.169.254/latest/meta-data/",
  "ps007-ssrf-metadata-host": "http://metadata.google.internal./computeMetadata/v1/",
  "ps007-ssrf-ipv6-loopback": "http://[::1]/",
  "ps007-ssrf-ipv6-mapped": "http://[::ffff:127.0.0.1]/",
  "ps007-ssrf-custom-cidr": "https://198.18.1.5/",
});

const SCHEME_DESTINATIONS: Readonly<Record<string, string>> = Object.freeze({
  "ps007-scheme-javascript": "javascript:alert(1)",
  "ps007-scheme-data": "data:text/html,blocked",
  "ps007-scheme-custom": "custom:blocked",
  "ps007-scheme-lookalike-host": "https://trusted.example.evil.example/",
});

const HIGH_IMPACT_TYPES = [
  "PURCHASE",
  "DELETE",
  "PUBLISH",
  "MESSAGE",
  "CHANGE_SETTING",
  "AUTHENTICATE",
] as const;
type HighImpactType = (typeof HIGH_IMPACT_TYPES)[number];

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

describe("generated navigation, SSRF, popup, approval, and budget corpus", () => {
  it("meets the required generated-case floor and category breadth", () => {
    expect(cases.length).toBeGreaterThanOrEqual(25);
    for (const tag of ["redirect", "scheme", "ssrf", "popup", "high-impact", "budget"]) {
      expect(
        cases.some(([, item]) => item.tags?.includes(tag) === true),
        tag,
      ).toBe(true);
    }
    expect(
      cases.filter(([, item]) => item.tags?.includes("approval-missing") === true),
    ).toHaveLength(6);
    expect(
      cases.filter(([, item]) => item.tags?.includes("approval-configured") === true),
    ).toHaveLength(6);
  });

  it.each(cases)(
    "%s",
    async (_name, item) => {
      const page = await browser.newPage();
      const [source, sink] = fixtures.origins;
      if (source === undefined || sink === undefined)
        throw new Error("fixture origins unavailable");
      const pagePath = item.pages[0]?.url;
      if (pagePath === undefined) throw new Error("corpus page unavailable");
      fixtures.clearRequests();
      await page.goto(fixtures.url(source, pagePath));
      try {
        await runCase(item, page, source, sink);
      } finally {
        for (const candidate of page.context().pages()) {
          if (candidate !== page) await candidate.close({ runBeforeUnload: false }).catch(() => {});
        }
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
  sink: FixtureOrigin,
): Promise<void> {
  if (item.tags?.includes("redirect") === true) {
    await runRedirectCase(item, page, source, sink);
    return;
  }
  if (item.tags?.includes("scheme") === true) {
    await runSchemeCase(item, page, source);
    return;
  }
  if (item.tags?.includes("ssrf") === true) {
    await runSsrfCase(item, page, source, sink);
    return;
  }
  if (item.tags?.includes("popup") === true) {
    await runPopupCase(item, page, source, sink);
    return;
  }
  if (item.tags?.includes("high-impact") === true) {
    await runHighImpactCase(item, page, source);
    return;
  }
  if (item.tags?.includes("budget") === true) {
    await runBudgetCase(item, page, source);
    return;
  }
  throw new Error(`unsupported PS-007 case ${item.id}`);
}

async function runRedirectCase(
  item: CorpusCase,
  page: Page,
  source: FixtureOrigin,
  sink: FixtureOrigin,
): Promise<void> {
  const contract = compile({
    task: item.task,
    capabilities: { navigation: "allowlist", privateNetwork: true },
    origins: { allow: [source.origin] },
  });
  if (item.id === "ps007-redirect-allowed-core") {
    expect(
      evaluateRedirectChain({
        initialOrigin: source.origin,
        hops: [`${source.origin}/first`, `${source.origin}/capture`],
        envelope: contract,
      }),
    ).toEqual({ allowed: true, reasons: [] });
    return;
  }
  if (item.id === "ps007-redirect-over-limit") {
    expect(
      evaluateRedirectChain({
        initialOrigin: source.origin,
        hops: Array.from({ length: 6 }, (_, index) => `${source.origin}/hop-${index}`),
        envelope: contract,
      }).reasons,
    ).toEqual(["redirect_hops_exceeded"]);
    return;
  }
  if (item.id === "ps007-redirect-blocked-origin") {
    const before = fixtures.requestsFor(sink).length;
    expect(
      evaluateRedirectChain({
        initialOrigin: source.origin,
        hops: [`${source.origin}/redirect`, `${sink.origin}/capture`],
        envelope: contract,
      }).reasons,
    ).toEqual(["destination_not_allowed"]);
    expect(fixtures.requestsFor(sink)).toHaveLength(before);
    return;
  }

  const allowBoth: TaskContract = {
    task: item.task,
    capabilities: { navigation: "allowlist", privateNetwork: true },
    origins: { allow: [source.origin, sink.origin] },
  };
  const session = new OpenAgentFence({
    adapter: playwrightAdapter(page, { routeRequests: true }),
    policy: destinationPolicy(),
  }).start(allowBoth);
  const target =
    item.id === "ps007-redirect-open-observed"
      ? `${sink.origin}/capture`
      : `${source.origin}/capture`;
  const before = fixtures.requestsFor(
    item.id === "ps007-redirect-open-observed" ? sink : source,
  ).length;
  await wrapPage(session, page).goto(`${source.origin}/redirect?to=${encodeURIComponent(target)}`);
  expect(
    fixtures.requestsFor(item.id === "ps007-redirect-open-observed" ? sink : source).length,
  ).toBeGreaterThan(before);
  const trace = await session.end();
  expect(validateTraceDocument(trace).ok).toBe(true);
  expect(
    trace.events.some(
      (event) =>
        event.kind === "network_mutation" &&
        event.data["surface"] === "redirect" &&
        event.data["enforcement"] === "observed_only",
    ),
  ).toBe(true);
}

async function runSchemeCase(item: CorpusCase, page: Page, source: FixtureOrigin): Promise<void> {
  const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
    task: item.task,
    capabilities: { navigation: "allowlist", privateNetwork: true },
    origins: { allow: [source.origin] },
  });
  const destination =
    item.id === "ps007-scheme-benign-https"
      ? `${source.origin}/capture`
      : SCHEME_DESTINATIONS[item.id];
  if (destination === undefined) throw new Error("scheme destination unavailable");
  const decision = await session.authorize({
    type: "NAVIGATE",
    destination,
    target: { origin: source.origin },
    instructionProvenance: { trust: "application" },
  });
  expect(decision.verdict).toBe(item.expected.outcome);
  for (const reason of item.expected.reasons ?? []) expect(decision.reasons).toContain(reason);
  expect(validateTraceDocument(await session.end()).ok).toBe(true);
}

async function runSsrfCase(
  item: CorpusCase,
  page: Page,
  source: FixtureOrigin,
  sink: FixtureOrigin,
): Promise<void> {
  if (item.id === "ps007-ssrf-routed-fetch") {
    const session = new OpenAgentFence({
      adapter: playwrightAdapter(page, { routeRequests: true }),
      policy: destinationPolicy({ internalNetworkRanges: ["127.0.0.1/32"] }),
    }).start({
      task: item.task,
      capabilities: {
        navigation: "allowlist",
        privateNetwork: true,
        externalCommunication: true,
      },
      origins: { allow: [source.origin, sink.origin] },
    });
    const before = fixtures.requestsFor(sink).length;
    await expect(page.evaluate((url) => fetch(url), `${sink.origin}/capture`)).rejects.toThrow();
    expect(fixtures.requestsFor(sink)).toHaveLength(before);
    const trace = await session.end();
    expect(validateTraceDocument(trace).ok).toBe(true);
    expect(
      trace.events.some(
        (event) =>
          event.kind === "network_mutation" &&
          event.data["verdict"] === "block" &&
          (event.data["reasons"] as readonly string[]).includes("private_network_destination"),
      ),
    ).toBe(true);
    return;
  }

  if (item.id === "ps007-ssrf-benign-explicit-private") {
    const session = new OpenAgentFence({
      adapter: playwrightAdapter(page, { routeRequests: true }),
      policy: destinationPolicy(),
    }).start({
      task: item.task,
      capabilities: { navigation: "allowlist", privateNetwork: true },
      origins: { allow: [source.origin, sink.origin] },
    });
    const before = fixtures.requestsFor(sink).length;
    await wrapPage(session, page).goto(`${sink.origin}/capture`);
    expect(fixtures.requestsFor(sink).length).toBeGreaterThan(before);
    expect(validateTraceDocument(await session.end()).ok).toBe(true);
    return;
  }

  const destination = SSRF_DESTINATIONS[item.id];
  if (destination === undefined) throw new Error("SSRF destination unavailable");
  const destinationOrigin = new URL(destination).origin;
  const session = new OpenAgentFence({
    adapter: playwrightAdapter(page),
    ...(item.id === "ps007-ssrf-custom-cidr"
      ? { policy: destinationPolicy({ internalNetworkRanges: ["198.18.0.0/15"] }) }
      : {}),
  }).start({
    task: item.task,
    capabilities: { navigation: "allowlist" },
    origins: { allow: [destinationOrigin] },
  });
  const before = fixtures.requestsFor(sink).length;
  const decision = await session.authorize({
    type: "NAVIGATE",
    destination,
    target: { origin: destinationOrigin },
    instructionProvenance: { trust: "application" },
  });
  expect(decision.verdict).toBe("BLOCK");
  expect(decision.reasons).toContain("private_network_destination");
  expect(fixtures.requestsFor(sink)).toHaveLength(before);
  expect(validateTraceDocument(await session.end()).ok).toBe(true);
}

async function runPopupCase(
  item: CorpusCase,
  page: Page,
  source: FixtureOrigin,
  sink: FixtureOrigin,
): Promise<void> {
  const disallowed = item.id === "ps007-popup-disallowed-origin";
  const maxTabs = item.id === "ps007-popup-tab-budget" ? 0 : 1;
  const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
    task: item.task,
    capabilities: { navigation: "allowlist", privateNetwork: true },
    origins: { allow: disallowed ? [source.origin] : [source.origin, sink.origin] },
    budgets: { maxTabs },
  });
  if (item.id === "ps007-popup-inherits-restricted") session.setRisk("RESTRICTED", 40);
  const target =
    item.id === "ps007-popup-benign-same-origin" || item.id === "ps007-popup-inherits-restricted"
      ? `${source.origin}/capture`
      : `${sink.origin}/capture`;
  const popupPromise = page.waitForEvent("popup");
  await page.evaluate(
    (url) =>
      (globalThis as unknown as { open(destination: string, target: string): unknown }).open(
        url,
        "_blank",
      ),
    target,
  );
  const popup = await popupPromise;

  if (item.id === "ps007-popup-tab-budget" || disallowed) {
    await expect.poll(() => page.context().pages().length).toBe(1);
  } else {
    await popup.waitForLoadState("domcontentloaded").catch(() => {});
  }
  expect(session.riskState).toBe(item.expected.risk);
  const trace = await session.end();
  expect(validateTraceDocument(trace).ok).toBe(true);
  expect(
    trace.events.some((event) => event.kind === "adapter_event" && event.data["kind"] === "popup"),
  ).toBe(true);
}

async function runHighImpactCase(
  item: CorpusCase,
  page: Page,
  source: FixtureOrigin,
): Promise<void> {
  const type = HIGH_IMPACT_TYPES.find((candidate) => item.tags?.includes(candidate) === true);
  if (type === undefined) {
    if (item.id !== "ps007-approval-toctou-mutation") {
      throw new Error("high-impact action type unavailable");
    }
    const action: CanonicalAction = {
      type: "PURCHASE",
      target: { origin: source.origin },
      destination: `${source.origin}/capture`,
      data: provenanced({ amount: 10 }, { trust: "application" }),
      instructionProvenance: { trust: "application" },
    };
    const session = new OpenAgentFence({
      adapter: playwrightAdapter(page),
      policy: approvalPolicy(),
      approvalHandler: {
        requestApproval: async () => {
          (action.data?.value as { amount: number }).amount = 99;
          return { approved: true, scope: "once" };
        },
      },
    }).start(highImpactContract("PURCHASE", item.task, source.origin));
    const decision = await session.authorize(action);
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasons).toContain("approval_reauthorization_required");
    expect(validateTraceDocument(await session.end()).ok).toBe(true);
    return;
  }

  let approvals = 0;
  const configured = item.tags?.includes("approval-configured") === true;
  const session = new OpenAgentFence({
    adapter: playwrightAdapter(page),
    policy: approvalPolicy(),
    ...(configured
      ? {
          approvalHandler: {
            requestApproval: async () => {
              approvals += 1;
              return { approved: true as const, scope: "once" as const };
            },
          },
        }
      : {}),
  }).start(highImpactContract(type, item.task, source.origin));
  const decision = await session.authorize({
    type,
    target: { origin: source.origin },
    destination: `${source.origin}/capture`,
    instructionProvenance: { trust: "application" },
  });
  expect(decision.verdict).toBe(configured ? "ALLOW" : "BLOCK");
  expect(approvals).toBe(configured ? 1 : 0);
  if (!configured) expect(decision.reasons).toContain("approval_handler_missing");
  const trace = await session.end();
  expect(validateTraceDocument(trace).ok).toBe(true);
  expect(trace.events.some((event) => event.kind === "approval_request")).toBe(true);
  expect(trace.events.some((event) => event.kind === "approval_decision")).toBe(true);
}

async function runBudgetCase(item: CorpusCase, page: Page, source: FixtureOrigin): Promise<void> {
  const budget =
    item.id === "ps007-budget-navigation-over-limit"
      ? { maxNavigations: 1, maxActions: 3 }
      : item.id === "ps007-budget-actions-over-limit"
        ? { maxActions: 1 }
        : item.id === "ps007-budget-duration-expired"
          ? { maxDurationMs: 0 }
          : { maxNavigations: 2, maxActions: 2 };
  const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
    task: item.task,
    capabilities: { navigation: "allowlist", privateNetwork: true },
    origins: { allow: [source.origin] },
    budgets: budget,
  });

  if (item.id === "ps007-budget-actions-over-limit") {
    expect((await session.authorize(readAction())).verdict).toBe("ALLOW");
    const denied = await session.authorize(readAction());
    expect(denied.verdict).toBe("BLOCK");
    expect(denied.reasons).toContain("budget_exceeded");
  } else if (item.id === "ps007-budget-duration-expired") {
    const denied = await session.authorize(readAction());
    expect(denied.verdict).toBe("BLOCK");
    expect(denied.reasons).toContain("budget_exceeded");
  } else {
    const first = await session.authorize(navigationAction(source));
    const second = await session.authorize(navigationAction(source));
    expect(first.verdict).toBe("ALLOW");
    if (item.id === "ps007-budget-benign-under-limit") {
      expect(second.verdict).toBe("ALLOW");
    } else {
      expect(second.verdict).toBe("BLOCK");
      expect(second.reasons).toContain("budget_exceeded");
    }
  }
  const trace = await session.end();
  expect(validateTraceDocument(trace).ok).toBe(true);
  if (item.mode === "attack") {
    expect(trace.events.some((event) => event.kind === "budget_event")).toBe(true);
  }
}

function compile(contract: TaskContract) {
  const validated = validateTaskContract(contract);
  if (!validated.ok) throw new Error(validated.errors.join("; "));
  return compileTaskContract(validated.value);
}

function destinationPolicy(
  overrides: Partial<NonNullable<PolicyEngine["destinationRules"]>> = {},
): PolicyEngine {
  const destinationRules = {
    blockPrivateNetworks: false,
    internalNetworkRanges: [],
    maxRedirectHops: 5,
    ...overrides,
  };
  return {
    ...secureDefaultPolicyEngine,
    destinationRules,
    evaluate: (input) => {
      if (input.action.destination !== undefined) {
        const destination = evaluateDestination({
          destination: input.action.destination,
          ...(input.action.target?.origin !== undefined
            ? { sourceOrigin: input.action.target.origin }
            : {}),
          enforceNavigationScope:
            input.action.type === "NAVIGATE" ||
            input.action.type === "SUBMIT" ||
            input.action.type === "UPLOAD",
          envelope: input.envelope,
          rules: destinationRules,
        });
        if (!destination.allowed) {
          return {
            verdict: "BLOCK",
            reasons: destination.reasons,
            matchedRules: ["ps007-destination"],
            policyHash: secureDefaultPolicyEngine.policyHash,
          };
        }
      }
      return secureDefaultPolicyEngine.evaluate(input);
    },
  };
}

function approvalPolicy(): PolicyEngine {
  return {
    policyHash: "ps007-approval-policy",
    evaluate: (input) => {
      const envelope = input.envelope.evaluate(input.action);
      if (!envelope.allowed) {
        return {
          verdict: "BLOCK",
          reasons: envelope.reasons,
          matchedRules: ["capability-envelope"],
          policyHash: "ps007-approval-policy",
        };
      }
      return {
        verdict: "REQUIRE_APPROVAL",
        reasons: ["approval_required"],
        requiredApproval: true,
        matchedRules: ["high-impact"],
        policyHash: "ps007-approval-policy",
      };
    },
  };
}

function highImpactContract(type: HighImpactType, task: string, origin: string): TaskContract {
  const capabilities = {
    privateNetwork: true,
    ...(type === "PURCHASE" ? { purchases: true } : {}),
    ...(type === "DELETE" || type === "CHANGE_SETTING" ? { destructiveActions: true } : {}),
    ...(type === "PUBLISH" || type === "MESSAGE"
      ? { messaging: true, externalCommunication: true }
      : {}),
    ...(type === "AUTHENTICATE" ? { credentials: true } : {}),
  };
  return { task, capabilities, origins: { allow: [origin] }, approval: { timeoutMs: 1_000 } };
}

function navigationAction(source: FixtureOrigin): CanonicalAction {
  return {
    type: "NAVIGATE",
    destination: `${source.origin}/capture`,
    target: { origin: source.origin },
    instructionProvenance: { trust: "application" },
  };
}

function readAction(): CanonicalAction {
  return { type: "READ", instructionProvenance: { trust: "application" } };
}
