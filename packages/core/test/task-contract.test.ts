import { describe, expect, it } from "vitest";
import { validateTaskContract } from "../src/index.js";

describe("task contract validation", () => {
  it("accepts a valid contract and freezes it", () => {
    const result = validateTaskContract({
      task: "find a hotel",
      capabilities: { downloads: true },
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(Object.isFrozen(result.value)).toBe(true);
      expect(result.value.task).toBe("find a hotel");
      expect(result.value.capabilities?.downloads).toBe(true);
    }
  });

  it("rejects unknown top-level keys", () => {
    const result = validateTaskContract({ task: "x", bogus: 1 });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join(" ")).toContain("bogus");
    }
  });

  it("rejects unknown capability keys", () => {
    const result = validateTaskContract({ task: "x", capabilities: { hacker: true } });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join(" ")).toContain("hacker");
    }
  });

  it("rejects a missing or empty task", () => {
    expect(validateTaskContract({}).ok).toBe(false);
    expect(validateTaskContract({ task: "  " }).ok).toBe(false);
  });

  it("rejects invalid enums and types", () => {
    expect(validateTaskContract({ task: "x", capabilities: { navigation: "moon" } }).ok).toBe(
      false,
    );
    expect(validateTaskContract({ task: "x", budgets: { maxActions: "many" } }).ok).toBe(false);
    expect(
      validateTaskContract({
        task: "x",
        secrets: [{ name: "a", kind: "SECRET", origins: [], fieldTypes: [] }],
      }).ok,
    ).toBe(true);
  });
});
