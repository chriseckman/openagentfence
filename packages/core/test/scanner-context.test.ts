import { describe, expect, it } from "vitest";
import {
  buildScopedView,
  definePluginScanner,
  defineScanner,
  runPhase,
  ScannerRegistry,
} from "../src/index.js";
import { mkContext, mkAction } from "./helpers.js";

describe("defineScanner", () => {
  it("returns a frozen scanner", () => {
    const s = defineScanner({
      id: "s",
      phases: ["PERCEPTION"],
      kind: "deterministic",
      scan: async () => ({
        scanner: "s",
        kind: "deterministic" as const,
        verdict: "allow" as const,
        severity: "low" as const,
        findings: [],
      }),
    });
    expect(Object.isFrozen(s)).toBe(true);
  });

  it("rejects a scanner without phases", () => {
    expect(() =>
      defineScanner({
        id: "s",
        phases: [],
        kind: "deterministic",
        scan: async () => ({
          scanner: "s",
          kind: "deterministic" as const,
          verdict: "allow" as const,
          severity: "low" as const,
          findings: [],
        }),
      }),
    ).toThrow();
  });
});

describe("scoped context views (least privilege)", () => {
  it("routes permissioned plugins through the scoped production wrapper", async () => {
    const secret = "plugin-production-sentinel-9821";
    const seen: unknown[] = [];
    const plugin = definePluginScanner({
      id: "scoped-plugin",
      phases: ["PRE_ACTION"],
      kind: "deterministic",
      manifest: {
        id: "scoped-plugin",
        permissions: ["action:metadata"],
        network: false,
      },
      scan: async (view) => {
        seen.push(view);
        return {
          scanner: "scoped-plugin",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      },
    });
    const registry = new ScannerRegistry();
    registry.register(plugin);
    const ctx = mkContext("PRE_ACTION", {
      kind: "proposedAction",
      action: mkAction("FILL", { data: secret }),
    });
    ctx.redactor.registerSecret(secret);
    await runPhase(registry, "PRE_ACTION", ctx);
    expect(seen).toHaveLength(1);
    expect(JSON.stringify(seen)).not.toContain(secret);
    expect((seen[0] as { action?: Record<string, unknown> }).action?.["data"]).toBeUndefined();
  });

  it("rejects permissioned scanners that bypass the scoped wrapper", () => {
    expect(() =>
      defineScanner({
        id: "unsafe-plugin",
        phases: ["PRE_ACTION"],
        kind: "deterministic",
        permissions: ["action:metadata"],
        scan: async () => ({
          scanner: "unsafe-plugin",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        }),
      }),
    ).toThrow("definePluginScanner");

    const registry = new ScannerRegistry();
    expect(() =>
      registry.register({
        id: "direct-plugin",
        phases: ["PRE_ACTION"],
        kind: "deterministic",
        permissions: ["action:metadata"],
        scan: async () => ({
          scanner: "direct-plugin",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        }),
      }),
    ).toThrow("definePluginScanner");
  });

  it("rejects unsupported plugin network authority", () => {
    expect(() =>
      definePluginScanner({
        id: "network-plugin",
        phases: ["PERCEPTION"],
        kind: "deterministic",
        manifest: { id: "network-plugin", permissions: [], network: true },
        scan: async () => ({
          scanner: "network-plugin",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        }),
      }),
    ).toThrow("network access is unavailable");
  });

  it("omits observation and action data when only action:metadata is granted", () => {
    const ctx = mkContext("PRE_ACTION", {
      kind: "proposedAction",
      action: mkAction("FILL", { data: "<SECRET:api:abcdefabcdefabcdefabcdefabcdefab>" }),
    });
    const view = buildScopedView(ctx, ["action:metadata"]);
    expect(view.observation).toBeUndefined();
    expect(view.action).toBeDefined();
    expect(view.action?.["data"]).toBeUndefined();
    expect(view.action?.["type"]).toBe("FILL");
  });

  it("includes handles only with secrets:handles permission", () => {
    const ctx = mkContext("PRE_ACTION", {
      kind: "proposedAction",
      action: mkAction("FILL", { data: "<SECRET:api:abcdefabcdefabcdefabcdefabcdefab>" }),
    });
    expect(buildScopedView(ctx, ["action:metadata"]).handles).toBeUndefined();
    expect(buildScopedView(ctx, ["secrets:handles"]).handles?.length).toBe(1);
  });

  it("redacts page text in a scoped observation view", () => {
    const ctx = mkContext("PERCEPTION", {
      kind: "observation",
      observation: {
        url: "https://example.com",
        origin: "https://example.com",
        frames: [],
        ariaSnapshot: "secret-token-1234 visible text",
        provenance: { trust: "web" },
      },
    });
    ctx.redactor.registerSecret("secret-token-1234");
    const view = buildScopedView(ctx, ["page:visible_text"]);
    const snapshot = view.observation?.["ariaSnapshot"];
    expect(snapshot).toBeDefined();
    expect(String(snapshot)).not.toContain("secret-token-1234");
  });

  it("redacts registered values before action data reaches a plugin", () => {
    const secret = "plugin-egress-sentinel-9821";
    const ctx = mkContext("PRE_ACTION", {
      kind: "proposedAction",
      action: mkAction("MESSAGE", { data: { nested: [secret] } }),
    });
    ctx.redactor.registerSecret(secret);
    const view = buildScopedView(ctx, ["action:data"]);
    expect(JSON.stringify(view.action)).not.toContain(secret);
    expect(JSON.stringify(view.action)).toContain("[REDACTED]");
  });
});
