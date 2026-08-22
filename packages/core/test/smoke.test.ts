import { describe, expect, it } from "vitest";
import { OpenAgentFence } from "../src/index.js";
import { secureDefaultPolicyEngine } from "../src/index.js";
import { REASON_CODES } from "../src/index.js";

describe("@openagentfence/core", () => {
  it("exposes the facade and engine", () => {
    expect(typeof OpenAgentFence).toBe("function");
    expect(typeof secureDefaultPolicyEngine.evaluate).toBe("function");
  });

  it("exposes the reason-code registry", () => {
    expect(REASON_CODES.capability_denied).toBe("capability_denied");
  });
});
