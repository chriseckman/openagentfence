import { describe, expect, it } from "vitest";
import { dependencyViolations } from "../../../scripts/dependency-rules.mjs";

describe("dependency-direction rules (ARCHITECTURE §3)", () => {
  it("allows the documented downward edges", () => {
    const ok = dependencyViolations({
      policy: ["core"],
      vault: ["core"],
      scanners: ["core"],
      providers: ["core"],
      playwright: ["core"],
      stagehand: ["core", "playwright"],
      testing: ["core", "scanners", "policy"],
      cli: ["core", "policy", "scanners", "testing", "providers", "vault"],
    });
    expect(ok).toEqual([]);
  });

  it("rejects a core -> sibling edge", () => {
    const violations = dependencyViolations({ core: ["policy"] });
    expect(violations).toHaveLength(1);
    expect(violations[0]?.package).toBe("core");
    expect(violations[0]?.dependency).toBe("policy");
  });

  it("rejects adapters importing scanners or policy", () => {
    expect(dependencyViolations({ playwright: ["scanners"] })).toHaveLength(1);
    expect(dependencyViolations({ stagehand: ["policy"] })).toHaveLength(1);
  });

  it("rejects any package importing cli", () => {
    expect(dependencyViolations({ testing: ["cli"] })).toHaveLength(1);
    expect(dependencyViolations({ core: ["cli"] })).toHaveLength(1);
  });

  it("flags unknown packages", () => {
    const violations = dependencyViolations({ notapackage: ["core"] });
    expect(violations).toHaveLength(1);
    expect(violations[0]?.reason).toContain("unknown package");
  });
});
