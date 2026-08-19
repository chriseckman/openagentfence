import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startFixtureServer, type FixtureOrigin, type FixtureServer } from "../src/index.js";

let server: FixtureServer;

beforeAll(async () => {
  server = await startFixtureServer({ originCount: 2 });
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

  it("redirects and captures the request", async () => {
    const origin = originAt(0);
    const res = await fetch(`${origin.origin}/redirect?to=/capture`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/capture");
    expect(server.requests.some((r) => r.url.includes("/redirect"))).toBe(true);
  });

  it("captures a POST body", async () => {
    const origin = originAt(0);
    await fetch(`${origin.origin}/capture`, { method: "POST", body: "token=abc" });
    expect(server.requests.some((r) => r.method === "POST" && r.body.includes("token=abc"))).toBe(
      true,
    );
  });

  it("serves a download attachment and a popup page", async () => {
    const origin = originAt(0);
    const download = await fetch(`${origin.origin}/download`);
    expect(download.headers.get("content-disposition")).toContain("attachment");

    const popup = await fetch(`${origin.origin}/popup`);
    expect(await popup.text()).toContain("window.open");
  });
});
