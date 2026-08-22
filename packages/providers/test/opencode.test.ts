import { describe, expect, it } from "vitest";
import {
  GuardProviderConstructionError,
  guardProvider,
  openCodeGuardProvider,
} from "../src/index.js";

describe("optional OpenCode provider", () => {
  it("keeps the default package import OpenCode-free", async () => {
    const imported = await import("../src/index.js");
    expect(imported.PACKAGE_NAME).toBe("@openagentfence/providers");
    expect(imported.openCodeGuardProvider).toBe(openCodeGuardProvider);
  });

  it("fails valid construction with typed unavailable evidence", () => {
    expect(() =>
      guardProvider("opencode", {
        model: "configured-provider/configured-model",
        baseUrl: "http://127.0.0.1:4096",
      }),
    ).toThrow(GuardProviderConstructionError);
    try {
      openCodeGuardProvider({
        model: "configured-provider/configured-model",
        baseUrl: "http://127.0.0.1:4096",
      });
    } catch (error) {
      expect(error).toMatchObject({ code: "provider_unavailable" });
    }
  });

  it("rejects absent or unsupported configuration without leaking credentials", () => {
    const sentinel = "synthetic-opencode-server-password";
    for (const options of [
      { model: "", apiKey: sentinel },
      { model: "fixture", apiKey: sentinel, baseUrl: "file:///unsafe" },
      { model: "fixture", apiKey: sentinel, unsupported: true },
    ]) {
      try {
        guardProvider("opencode", options as never);
        throw new Error("expected construction failure");
      } catch (error) {
        expect(error).toBeInstanceOf(GuardProviderConstructionError);
        expect(JSON.stringify(error)).not.toContain(sentinel);
        expect((error as Error).message).not.toContain(sentinel);
      }
    }
  });
});
