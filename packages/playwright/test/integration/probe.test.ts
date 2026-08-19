import { chromium } from "playwright";
import { createServer } from "node:http";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  buildProbeScript,
  secureDefaultPolicyEngine,
  runAdapterConformance,
  type PolicyEngine,
  validateProbeResult,
} from "@openagentfence/core";
import { startFixtureServer, type FixtureServer } from "@openagentfence/testing";
import { PLAYWRIGHT_NETWORK_CAPABILITIES, playwrightAdapter } from "../../src/index.js";
import type { Browser, Page } from "playwright";

let browser: Browser;

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser.close();
});

async function runProbe(page: Page) {
  const raw = await page.evaluate<unknown>(buildProbeScript());
  return validateProbeResult(raw);
}

describe("probe signals (OAF-CORE-014)", () => {
  it("collects visual, geometry, pseudo-element, comment, metadata, and frame signals", async () => {
    const page = await browser.newPage();
    await page.setContent(`
      <!doctype html>
      <html>
        <head>
          <title>Probe Test</title>
          <meta name="description" content="desc">
          <script type="application/ld+json">{"@context":"https://schema.org","@type":"Thing","name":"x"}</script>
          <style>
            .big { font-size: 40px; }
            .pseudo::before { content: "BEFORE"; }
          </style>
        </head>
        <body>
          <!-- a hidden comment instruction -->
          <div id="visible" class="big" style="color: rgb(1, 2, 3)">Visible text</div>
          <div id="offscreen" style="position:absolute; left:-10000px">Offscreen text</div>
          <div id="pseudo" class="pseudo">pseudo el</div>
          <noscript><div>noscript content</div></noscript>
          <svg><text id="svgtext">SVG text</text></svg>
          <a href="https://example.com/x">a link</a>
        </body>
      </html>
    `);

    const probe = await runProbe(page);
    expect(probe).not.toBeNull();
    expect(probe?.probeVersion).toBe(2);
    expect(probe?.truncated).toBe(false);

    const nodes = probe?.nodes ?? [];
    const bySelector = (sel: string) => nodes.find((n) => n.selector === sel);

    expect(bySelector("#visible")?.fontSize).toBe("40px");
    expect(bySelector("#visible")?.color).toBe("rgb(1, 2, 3)");
    expect(bySelector("#visible")?.inViewport).toBe(true);
    expect(bySelector("#offscreen")?.inViewport).toBe(false);
    expect(bySelector("#pseudo")?.pseudoBefore).toBe("BEFORE");
    expect(nodes.some((n) => n.tagName === "text" && n.text === "SVG text")).toBe(true);
    expect(probe?.comments).toContain("a hidden comment instruction");
    expect(probe?.metadata.title).toBe("Probe Test");
    expect(probe?.metadata.meta["description"]).toBe("desc");
    expect(probe?.metadata.jsonLd.join("")).toContain("schema.org");
    expect(probe?.metadata.noscript.join(" ")).toContain("noscript content");
    expect(probe?.links.some((l) => l.href === "https://example.com/x")).toBe(true);

    await page.close();
  });

  it("sets truncation flags on an oversized page rather than reporting clean", async () => {
    const page = await browser.newPage();
    const many = Array.from({ length: 20 }, (_, i) => `<i id="e${i}">x</i>`).join("");
    await page.setContent(`<html><body>${many}</body></html>`);

    const raw = await page.evaluate<unknown>(buildProbeScript({ maxNodes: 5, timeBudgetMs: 5000 }));
    const probe = validateProbeResult(raw);
    expect(probe).not.toBeNull();
    expect(probe?.truncated).toBe(true);
    expect(probe?.truncation.nodes).toBe(true);

    await page.close();
  });

  it("does not mutate the page", async () => {
    const page = await browser.newPage();
    await page.setContent(
      `<html><body><div id="a">one</div><div id="b" hidden>two</div></body></html>`,
    );
    const before = await page.content();

    const probe = await runProbe(page);
    expect(probe).not.toBeNull();

    const after = await page.content();
    expect(after).toBe(before);

    await page.close();
  });

  it("validates probe output through the adapter observation path", async () => {
    const page = await browser.newPage();
    await page.setContent(
      `<html><body><iframe srcdoc="<p>frame text</p>"></iframe><div id="v">hello</div></body></html>`,
    );
    const adapter = playwrightAdapter(page, { captureScreenshot: true });
    const observation = await adapter.observe();
    expect(observation.probe).toBeDefined();
    expect(observation.probe?.nodes.length).toBeGreaterThan(0);
    expect(observation.frames).toHaveLength(2);
    expect(
      observation.frames.every((frame) => frame.probe !== undefined && frame.id !== undefined),
    ).toBe(true);
    expect(observation.pageId).toMatch(/^pw-page-/);
    expect(observation.contextId).toMatch(/^pw-context-/);
    expect(observation.ariaSnapshot).toContain("hello");
    expect(observation.screenshot).toEqual(expect.any(String));
    expect(adapter.capabilities.screenshot).toBe(true);
    expect(adapter.capabilities.ariaSnapshot).toBe(true);
    expect(observation.provenance.trust).toBe("web");
    await page.close();
  });

  it("binds observable navigation and request effects to the supplied session", async () => {
    const page = await browser.newPage();
    await page.setContent(`<html><body>events</body></html>`);
    const adapter = playwrightAdapter(page);
    const events: Array<{
      readonly kind: string;
      readonly sessionId: string;
      readonly pageId?: string;
      readonly frameId?: string;
    }> = [];
    const mutations: Array<{
      readonly surface: string;
      readonly initiator: string;
      readonly origin?: string;
      readonly destination: string;
      readonly metadata?: { readonly headers: Readonly<Record<string, string>> };
    }> = [];
    const dispose = adapter.subscribe("session-under-test", {
      onNavigation: (event) => events.push(event),
      onPopup: (event) => {
        events.push(event);
        return false;
      },
      onDownload: (event) => events.push(event),
      onNetworkMutation: (mutation) => mutations.push(mutation),
    });
    const server = createServer((request, response) => {
      if (request.url === "/download") {
        response.setHeader("content-disposition", "attachment; filename=fixture.txt");
        response.end("download");
        return;
      }
      if (request.url === "/page") {
        response.setHeader("content-type", "text/html");
        response.end(
          '<a id="popup" href="/popup" target="_blank">popup</a><a id="download" href="/download">download</a><script>fetch("/api", { headers: { authorization: "synthetic-secret" } });</script>',
        );
        return;
      }
      response.end("local-event");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("fixture server did not bind");
    const baseUrl = `http://127.0.0.1:${address.port}`;
    await page.goto(`${baseUrl}/page`);
    await page.waitForTimeout(25);
    const popup = page.waitForEvent("popup");
    await page.locator("#popup").click();
    await popup;
    const download = page.waitForEvent("download");
    await page.locator("#download").click();
    await download;
    expect(events.map((event) => event.sessionId)).toContain("session-under-test");
    expect(events.some((event) => event.kind === "navigation" && event.frameId !== undefined)).toBe(
      true,
    );
    expect(events.some((event) => event.kind === "popup" && event.pageId !== undefined)).toBe(true);
    expect(events.some((event) => event.kind === "download" && event.pageId !== undefined)).toBe(
      true,
    );
    expect(
      mutations.some(
        (mutation) => mutation.surface === "navigation" && mutation.initiator === "unknown",
      ),
    ).toBe(true);
    expect(
      mutations.some(
        (mutation) => mutation.surface === "fetch" && mutation.initiator === "page_script",
      ),
    ).toBe(true);
    expect(
      mutations.some(
        (mutation) =>
          mutation.surface === "fetch" &&
          mutation.origin === baseUrl &&
          mutation.destination === `${baseUrl}/api`,
      ),
    ).toBe(true);
    expect(
      mutations.some((mutation) => mutation.metadata?.headers.authorization === "[REDACTED]"),
    ).toBe(true);
    const capturedBeforeDetach = events.length + mutations.length;
    dispose();
    await page.goto(`${baseUrl}/after-detach`);
    expect(events.length + mutations.length).toBe(capturedBeforeDetach);
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error === undefined ? resolve() : reject(error))),
    );
    await page.close();
  });

  it("reports only empirically observed network surfaces when routing is disabled", () => {
    expect(PLAYWRIGHT_NETWORK_CAPABILITIES).toEqual({
      navigation: "observed_only",
      redirect: "unavailable",
      form: "unavailable",
      fetch: "observed_only",
      headers: "unavailable",
      websocket: "observed_only",
      send_beacon: "unavailable",
      service_worker: "unavailable",
      upload: "unavailable",
      download: "unavailable",
      popup: "unavailable",
      webmcp: "unavailable",
    });
  });

  it("passes the framework-neutral adapter conformance suite", async () => {
    const page = await browser.newPage();
    await page.setContent("<main>conformance</main>");
    const report = await runAdapterConformance(playwrightAdapter(page));
    expect(report.ok).toBe(true);
    await page.close();
  });
});

describe("opt-in routed destination enforcement (OAF-SEC-001/002)", () => {
  let fixtures: FixtureServer | undefined;

  afterAll(async () => {
    await fixtures?.close();
  });

  afterEach(async () => {
    await fixtures?.close();
    fixtures = undefined;
  });

  it("aborts a private-range fetch before the target receives a request", async () => {
    fixtures = await startFixtureServer();
    const origin = fixtures.origins[0];
    if (origin === undefined) throw new Error("fixture origin missing");
    const page = await browser.newPage();
    await page.goto(`${origin.origin}/`);
    const policy = destinationPolicy({ internalNetworkRanges: ["127.0.0.1/32"] });
    const firewall = new (await import("@openagentfence/core")).OpenAgentFence({
      adapter: playwrightAdapter(page, { routeRequests: true }),
      policy,
    });
    const session = firewall.start({
      task: "read local fixture",
      capabilities: { privateNetwork: true, navigation: "allowlist" },
      origins: { allow: [origin.origin] },
    });
    const before = fixtures.requests.length;
    await expect(page.evaluate((url) => fetch(url), `${origin.origin}/capture`)).rejects.toThrow();
    expect(fixtures.requests).toHaveLength(before);
    await session.end();
    await page.close();
  });

  it("blocks an initial disallowed cross-origin navigation before its target receives bytes", async () => {
    fixtures = await startFixtureServer();
    const [originA, originB] = fixtures.origins;
    if (originA === undefined || originB === undefined) throw new Error("fixture origins missing");
    const page = await browser.newPage();
    await page.goto(`${originA.origin}/`);
    const firewall = new (await import("@openagentfence/core")).OpenAgentFence({
      adapter: playwrightAdapter(page, { routeRequests: true }),
      policy: destinationPolicy(),
    });
    const session = firewall.start({
      task: "follow trusted redirects",
      capabilities: { privateNetwork: true, navigation: "allowlist" },
      origins: { allow: [originA.origin] },
    });
    const beforeTarget = fixtures.requests.filter(
      (request) => request.origin === originB.origin,
    ).length;
    await expect(page.goto(`${originB.origin}/capture`)).rejects.toThrow();
    const afterTarget = fixtures.requests.filter(
      (request) => request.origin === originB.origin,
    ).length;
    expect(afterTarget).toBe(beforeTarget);
    await session.end();
    await page.close();
  });

  it("reports redirect hops as observed-only rather than claiming preflight enforcement", async () => {
    fixtures = await startFixtureServer();
    const [originA, originB] = fixtures.origins;
    if (originA === undefined || originB === undefined) throw new Error("fixture origins missing");
    const page = await browser.newPage();
    await page.goto(`${originA.origin}/`);
    const firewall = new (await import("@openagentfence/core")).OpenAgentFence({
      adapter: playwrightAdapter(page, { routeRequests: true }),
      policy: destinationPolicy(),
    });
    const session = firewall.start({
      task: "observe redirect coverage",
      capabilities: { privateNetwork: true, navigation: "allowlist" },
      origins: { allow: [originA.origin, originB.origin] },
    });
    const redirect = `${originA.origin}/redirect?to=${encodeURIComponent(`${originB.origin}/capture`)}`;
    await page.goto(redirect);
    const trace = await session.end();
    const redirectEvent = trace.events.find(
      (event) =>
        event.kind === "network_mutation" &&
        event.data["surface"] === "redirect" &&
        event.data["enforcement"] === "observed_only",
    );
    expect(redirectEvent).toBeDefined();
    expect(fixtures.requests.some((request) => request.origin === originB.origin)).toBe(true);
    await page.close();
  });
});

function destinationPolicy(
  overrides?: Partial<NonNullable<PolicyEngine["destinationRules"]>>,
): PolicyEngine {
  return {
    ...secureDefaultPolicyEngine,
    destinationRules: {
      blockPrivateNetworks: false,
      internalNetworkRanges: [],
      maxRedirectHops: 5,
      ...overrides,
    },
  };
}
