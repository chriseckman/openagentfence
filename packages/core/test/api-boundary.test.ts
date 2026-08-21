import * as core from "../src/index.js";
import { SecuritySession } from "../src/index.js";
import { describe, expect, it } from "vitest";

describe("v0.1 root API security boundaries", () => {
  it("does not publish raw vault construction or arbitrary exact-executor bridges", () => {
    expect(core).not.toHaveProperty("mintHandle");
    expect(core).not.toHaveProperty("createScopedSecretResolver");
    expect(core).not.toHaveProperty("createVaultExecutorAccess");
    expect(core).not.toHaveProperty("executeStagehandAuthorized");
    expect(SecuritySession.prototype).not.toHaveProperty("executeAuthorizedWith");
  });

  it("does not accept forged executor or raw-adapter access capabilities", () => {
    expect(core.isVaultExecutorAccess({})).toBe(false);
    expect(core.isUnsafeAdapterAccess({})).toBe(false);
  });
});
