import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FIXTURE_SERVER_LIMITS,
  startFixtureServer,
  type FixtureOrigin,
  type FixtureServer,
} from "../src/index.js";

let server: FixtureServer;

beforeAll(async () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "security-corpus");
  server = await startFixtureServer({ origins: ["source", "sink"], root });
});

afterAll(async () => {
  await server.close();
});

function originAt(index: number): FixtureOrigin {
  const origin = server.origins[index];
  if (origin === undefined) {
    throw new Error(`fixture server has no origin ${index}`);
  }
  return origin;
}

describe("fixture server (OAF-TEST-001)", () => {
  it("binds only loopback and serves two distinct origins", () => {
    expect(server.origins.length).toBe(2);
    for (const origin of server.origins) {
      expect(origin.host).toBe("127.0.0.1");
      expect(origin.origin).toBe(`http://127.0.0.1:${origin.port}`);
    }
    expect(server.origins[0]?.origin).not.toBe(server.origins[1]?.origin);
  });

  it("starts within one second and validates origin configuration", async () => {
    const started = Date.now();
    const temporary = await startFixtureServer({ origins: ["solo"] });
    expect(Date.now() - started).toBeLessThan(1_000);
    await temporary.close();
    await expect(startFixtureServer({ originCount: 9 })).rejects.toThrow();
    await expect(startFixtureServer({ origins: ["same", "same"] })).rejects.toThrow();
  });

  it("serves the hidden-DOM attack and benign fixtures", async () => {
    const origin = originAt(0);
    const attack = await fetch(`${origin.origin}/hidden-dom/display-none-instruction.html`);
    expect(attack.status).toBe(200);
    expect(await attack.text()).toContain("Ignore all previous instructions");

    const benign = await fetch(`${origin.origin}/hidden-dom/benign-skip-link.html`);
    expect(benign.status).toBe(200);
    expect(await benign.text()).toContain("skip to checkout");
  });

  it("serves the navigation and SSRF fixture pages from the local server", async () => {
    const origin = originAt(0);
    const privateLink = await fetch(`${origin.origin}/navigation/private-network-link.html`);
    expect(await privateLink.text()).toContain("169.254.169.254");
    const crossOrigin = await fetch(`${origin.origin}/navigation/cross-origin-link.html`);
    expect(await crossOrigin.text()).toContain("evil.example");
    const benign = await fetch(`${origin.origin}/navigation/benign-same-site-link.html`);
    expect(await benign.text()).toContain("/catalog");
  });

  it("serves corpus-root fixtures and rejects traversal", async () => {
    const origin = originAt(0);
    const multilingual = await fetch(
      server.url(origin, "/hidden-dom/multilingual-instruction.html"),
    );
    expect(multilingual.status).toBe(200);
    expect(await multilingual.text()).toContain("Ignora las instrucciones");
    const traversal = await fetch(server.url(origin, "/%2e%2e%2fREADME.md"));
    expect(traversal.status).toBe(404);
  });

  it("redirects and captures the request", async () => {
    const origin = originAt(0);
    const res = await fetch(`${origin.origin}/redirect?to=/capture`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/capture");
    expect(server.requests.some((r) => r.url.includes("/redirect"))).toBe(true);
  });

  it("captures a POST body", async () => {
    const origin = originAt(0);
    server.clearRequests();
    await fetch(`${origin.origin}/capture`, { method: "POST", body: "token=abc" });
    const captured = await server.waitForRequest((request) => request.method === "POST");
    expect(captured?.body).toContain("token=abc");
    expect(server.requestsFor("source")).toHaveLength(1);
  });

  it("drains oversized bodies but bounds captured content", async () => {
    const origin = originAt(0);
    server.clearRequests();
    const body = "x".repeat(FIXTURE_SERVER_LIMITS.maxRequestBodyBytes + 1);
    const response = await fetch(server.url(origin, "/echo"), { method: "POST", body });
    expect(response.status).toBe(413);
    const captured = server.requests[0];
    expect(captured?.bodyTruncated).toBe(true);
    expect(captured?.bodyBytes).toBe(body.length);
    expect(Buffer.byteLength(captured?.body ?? "", "utf8")).toBe(
      FIXTURE_SERVER_LIMITS.maxRequestBodyBytes,
    );
  });

  it("serves a download attachment and a popup page", async () => {
    const origin = originAt(0);
    const download = await fetch(`${origin.origin}/download`);
    expect(download.headers.get("content-disposition")).toContain("attachment");

    const popup = await fetch(`${origin.origin}/popup`);
    expect(await popup.text()).toContain("window.open");

    const mutation = await fetch(`${origin.origin}/mutation`);
    expect(await mutation.text()).toContain("setTimeout");
  });
});
