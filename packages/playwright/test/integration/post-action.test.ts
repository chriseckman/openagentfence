import { chromium } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OpenAgentFence } from "@openagentfence/core";
import { startFixtureServer } from "@openagentfence/testing";
import { playwrightAdapter, wrapPage } from "../../src/index.js";
import type { Browser } from "playwright";

let browser: Browser;

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser.close();
});

describe("bounded POST_ACTION validation", () => {
  it("detects a cross-origin script navigation after a guarded click", async () => {
    const fixtures = await startFixtureServer();
    const page = await browser.newPage();
    try {
      const [first, second] = fixtures.origins;
      if (first === undefined || second === undefined)
        throw new Error("fixture origins unavailable");
      await page.goto(first.origin);
      await page.setContent(
        `<button id="go" onclick="location.href='${second.origin}/'">continue</button>`,
      );
      const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
        task: "exercise a local redirect fixture",
      });
      await wrapPage(session, page).click("#go");
      expect(session.riskScore).toBeGreaterThan(0);
      const trace = await session.end();
      expect(JSON.stringify(trace)).toContain("unexpected_origin_change");
    } finally {
      await page.close();
      await fixtures.close();
    }
  });

  it("does not flag an authorized same-origin navigation as unexpected", async () => {
    const fixtures = await startFixtureServer({ originCount: 1 });
    const page = await browser.newPage();
    try {
      const [origin] = fixtures.origins;
      if (origin === undefined) throw new Error("fixture origin unavailable");
      await page.goto(origin.origin);
      const session = new OpenAgentFence({ adapter: playwrightAdapter(page) }).start({
        task: "follow a local catalog route",
        capabilities: { privateNetwork: true },
      });
      await wrapPage(session, page).goto(`${origin.origin}/catalog`);
      const trace = await session.end();
      const serialized = JSON.stringify(trace);
      expect(serialized).not.toContain("unexpected_redirect");
      expect(serialized).not.toContain("unexpected_origin_change");
    } finally {
      await page.close();
      await fixtures.close();
    }
  });
});
