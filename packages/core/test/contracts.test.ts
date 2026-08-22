import { describe, expect, it } from "vitest";
import { SCANNER_TO_AGGREGATE, AGGREGATE_VERDICTS, SCANNER_VERDICTS } from "../src/index.js";
import { leastTrust, TRUST_ORDER } from "../src/index.js";
import { maxRiskState } from "../src/index.js";
import { isSecurityPhase } from "../src/index.js";
import { provenanced, validateDataProvenance } from "../src/index.js";

describe("verdict vocabularies", () => {
  it("maps every scanner verdict to an aggregate verdict", () => {
    for (const v of SCANNER_VERDICTS) {
      expect(Object.values(AGGREGATE_VERDICTS)).toContain(SCANNER_TO_AGGREGATE[v]);
    }
    expect(SCANNER_TO_AGGREGATE.block).toBe("BLOCK");
    expect(SCANNER_TO_AGGREGATE.allow).toBe("ALLOW");
    expect(SCANNER_TO_AGGREGATE.sanitize).toBe("ALLOW_SANITIZED");
    expect(SCANNER_TO_AGGREGATE.approve).toBe("REQUIRE_APPROVAL");
  });
});

describe("provenance trust ordering", () => {
  it("orders web as least trusted", () => {
    expect(leastTrust("user", "web")).toBe("web");
    expect(leastTrust("application", "web")).toBe("web");
    expect(TRUST_ORDER[TRUST_ORDER.length - 1]).toBe("web");
  });

  it("memory is more trusted than web but less than user", () => {
    expect(leastTrust("web", "memory")).toBe("web");
    expect(leastTrust("memory", "user")).toBe("memory");
  });

  it("validates bounded closed provenance and preserves it in a datum carrier", () => {
    const provenance = {
      trust: "web" as const,
      origin: "https://example.test",
      frameOrigin: "https://frame.example.test",
      pageId: "page-1",
      elementId: "node-1",
      timestamp: "2026-08-19T00:00:00.000Z",
    };
    expect(validateDataProvenance(provenance)).toEqual(provenance);
    expect(provenanced("web-derived", provenance)).toEqual({ value: "web-derived", provenance });
    expect(validateDataProvenance({ trust: "web", extra: true })).toBeNull();
    expect(validateDataProvenance({ trust: "web", timestamp: "not-a-date" })).toBeNull();
    expect(validateDataProvenance({ trust: "bogus" })).toBeNull();
    expect(() => provenanced("x", { trust: "web", origin: "" })).toThrow(TypeError);
  });
});

describe("risk states", () => {
  it("are monotonic", () => {
    expect(maxRiskState("NORMAL", "RESTRICTED")).toBe("RESTRICTED");
    expect(maxRiskState("RESTRICTED", "QUARANTINED")).toBe("QUARANTINED");
  });
});

describe("phases", () => {
  it("recognizes valid phases only", () => {
    expect(isSecurityPhase("PERCEPTION")).toBe(true);
    expect(isSecurityPhase("BOGUS")).toBe(false);
  });
});
