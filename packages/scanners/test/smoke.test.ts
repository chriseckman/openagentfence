import { describe, expect, it } from "vitest";
import { defaultScanners } from "../src/index.js";

describe("@openagentfence/scanners", () => {
  it("exposes the default deterministic scanner catalog", () => {
    const scanners = defaultScanners();
    expect(scanners.length).toBeGreaterThanOrEqual(10);
    for (const s of scanners) {
      expect(s.kind).toBe("deterministic");
    }
    expect(scanners.some((scanner) => scanner.phases.includes("PERCEPTION"))).toBe(true);
    expect(scanners.find((scanner) => scanner.id === "cross-origin-navigation")?.phases).toEqual([
      "PRE_ACTION",
    ]);
    expect(scanners.find((scanner) => scanner.id === "local-network-ssrf")?.phases).toEqual([
      "PRE_ACTION",
    ]);
  });
});
