import { describe, expect, it } from "vitest";
import {
  expectBlocked,
  expectFinding,
  expectNoRawSecret,
  expectNoRawSecretIn,
  expectVerdict,
} from "../src/index.js";
import type { Finding } from "@openagentfence/core";

describe("testing assertions", () => {
  it("checks verdicts and finding categories", () => {
    expect(expectBlocked("BLOCK")).toBe(true);
    expect(expectBlocked({ verdict: "WARN" })).toBe(false);
    expect(expectVerdict({ verdict: "ALLOW" }, "ALLOW")).toBe(true);
    expect(
      expectFinding([{ category: "hidden_dom_instruction" } as Finding], "hidden_dom_instruction"),
    ).toBe(true);
  });

  it("checks multiple exact and normalized sentinels in cyclic/error artifacts", () => {
    const first = "Synthetic Secret With Spaces";
    const second = "second-synthetic-value";
    const safe: Record<string, unknown> = { error: new Error("redacted") };
    safe["cycle"] = safe;
    expect(expectNoRawSecret(safe, [first, second])).toBe(true);
    expect(expectNoRawSecretIn(safe, [first, second])).toBe(true);
    expect(expectNoRawSecretIn({ value: encodeURIComponent(first) }, [first, second])).toBe(false);
    expect(expectNoRawSecretIn({ value: first.toUpperCase() }, [first, second])).toBe(false);
    expect(
      expectNoRawSecretIn({ value: Buffer.from(first, "utf8").toString("base64") }, [first]),
    ).toBe(false);
    expect(expectNoRawSecret({ value: second }, [first, second])).toBe(false);
  });
});
