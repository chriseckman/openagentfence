import { describe, expect, it } from "vitest";
import { runAdapterConformance, validatePageObservation } from "../src/index.js";
import type { BrowserAdapter } from "../src/index.js";
import { fakeAdapter } from "./helpers.js";

describe("validatePageObservation", () => {
  it("accepts a well-formed observation", async () => {
    const obs = await fakeAdapter().observe();
    expect(validatePageObservation(obs)).toEqual([]);
  });

  it("rejects non-web provenance, missing url/origin, and bad frames", () => {
    expect(validatePageObservation(null)).not.toEqual([]);
    expect(validatePageObservation({ url: "u" })).not.toEqual([]);
    expect(
      validatePageObservation({
        url: "u",
        origin: "o",
        frames: [{ url: "u" }],
        provenance: { trust: "web" },
      }),
    ).not.toEqual([]);
    expect(
      validatePageObservation({
        url: "u",
        origin: "o",
        frames: [],
        provenance: { trust: "application" },
      }),
    ).not.toEqual([]);
  });
});

describe("runAdapterConformance", () => {
  it("passes a truthful fake adapter", async () => {
    const report = await runAdapterConformance(fakeAdapter());
    expect(report.ok).toBe(true);
    for (const check of report.checks) {
      expect(check.ok, check.name).toBe(true);
    }
  });

  it("fails an adapter whose observe throws", async () => {
    const adapter: BrowserAdapter = fakeAdapter({
      observe: async () => {
        throw new Error("boom");
      },
    });
    const report = await runAdapterConformance(adapter);
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name.startsWith("observe"))?.ok).toBe(false);
  });

  it("fails an adapter advertising a non-boolean capability", async () => {
    const adapter = fakeAdapter();
    const forged = {
      ...adapter,
      capabilities: { ...adapter.capabilities, route: "yes" },
    } as unknown as BrowserAdapter;
    const report = await runAdapterConformance(forged);
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === "capabilities.route")?.ok).toBe(false);
  });
});
