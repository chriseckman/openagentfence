import { describe, expect, it } from "vitest";
import { createCrossOriginNavigationScanner, createLocalNetworkSsrfScanner } from "../src/index.js";
import { probe, scannerContext } from "./helpers.js";

function proposed(destination: string, sourceOrigin = "https://shop.example") {
  const base = scannerContext(probe([]));
  return {
    ...base,
    phase: "PRE_ACTION" as const,
    payload: {
      kind: "proposedAction" as const,
      action: {
        type: "NAVIGATE" as const,
        destination,
        target: { origin: sourceOrigin },
        instructionProvenance: { trust: "web" as const },
      },
    },
  };
}

describe("navigation and SSRF advisory scanners (OAF-SEC-001/002)", () => {
  it("records an origin transition as advisory evidence", async () => {
    const result = await createCrossOriginNavigationScanner().scan(
      proposed("https://evil.example"),
    );
    expect(result.verdict).toBe("warn");
    expect(result.findings.map((finding) => finding.category)).toEqual(["cross_origin_navigation"]);
  });

  it.each([
    ["http://169.254.169.254/latest/meta-data/", "private_network_destination"],
    ["javascript:alert(1)", "unsafe_destination_scheme"],
  ])("emits bounded evidence for %s", async (destination, category) => {
    const result = await createLocalNetworkSsrfScanner().scan(proposed(destination));
    expect(result.verdict).toBe("warn");
    expect(result.findings.map((finding) => finding.category)).toEqual([category]);
  });

  it("does not flag a same-origin HTTPS navigation", async () => {
    const result = await createLocalNetworkSsrfScanner().scan(
      proposed("https://shop.example/cart"),
    );
    expect(result.findings).toEqual([]);
  });
});
