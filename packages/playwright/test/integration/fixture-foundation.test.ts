import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, firefox, webkit, type BrowserType } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startFixtureServer, type FixtureServer } from "@openagentfence/testing";

let fixtures: FixtureServer;

beforeAll(async () => {
  const root = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    "..",
    "..",
    "security-corpus",
  );
  fixtures = await startFixtureServer({ origins: ["source", "sink"], root });
});

afterAll(async () => {
  await fixtures.close();
});

describe("fixture foundation browser smoke", () => {
  it("runs static, mutation, and popup helpers in every locally installed engine", async () => {
    const engines = [chromium, firefox, webkit].filter(engineAvailable);
    expect(engines.map((engine) => engine.name())).toContain("chromium");

    for (const engine of engines) {
      fixtures.clearRequests();
      const browser = await engine.launch({ headless: true });
      try {
        const page = await browser.newPage();
        const origin = fixtures.origins[0];
        if (origin === undefined) throw new Error("fixture origin unavailable");

        await page.goto(fixtures.url(origin, "/hidden-dom/multilingual-instruction.html"));
        expect(await page.locator("main").textContent()).toContain("Reserva de hotel");

        await page.goto(fixtures.url(origin, "/mutation"));
        expect(
          await fixtures.waitForRequest(
            (request) => request.method === "POST" && request.body === "mut",
          ),
        ).not.toBeNull();

        const popupPromise = page.waitForEvent("popup");
        await page.goto(fixtures.url(origin, "/popup"));
        const popup = await popupPromise;
        await popup.waitForLoadState();
        expect(new URL(popup.url()).pathname).toBe("/capture");
        await popup.close();
      } finally {
        await browser.close();
      }
    }
  });
});

function engineAvailable(engine: BrowserType): boolean {
  return existsSync(engine.executablePath());
}
