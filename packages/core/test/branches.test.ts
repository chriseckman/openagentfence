import { describe, expect, it } from "vitest";
import {
  compileTaskContract,
  validateTaskContract,
  runWithDeadline,
  buildProbeScript,
  maxRiskState,
  sameSite,
} from "../src/index.js";
import type { ValidatedTaskContract } from "../src/index.js";

function contract(input: unknown): ValidatedTaskContract {
  const r = validateTaskContract(input);
  if (!r.ok) {
    throw new Error(r.errors.join("; "));
  }
  return r.value;
}

describe("task contract exhaustive validation", () => {
  it("rejects non-object input", () => {
    expect(validateTaskContract(null).ok).toBe(false);
    expect(validateTaskContract([]).ok).toBe(false);
    expect(validateTaskContract("x").ok).toBe(false);
  });

  it("rejects capability type errors", () => {
    expect(validateTaskContract({ task: "x", capabilities: "y" }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", capabilities: { downloads: "yes" } }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", capabilities: { navigation: 5 } }).ok).toBe(false);
  });

  it("rejects malformed secret bindings", () => {
    expect(validateTaskContract({ task: "x", secrets: "nope" }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", secrets: ["nope"] }).ok).toBe(false);
    expect(
      validateTaskContract({
        task: "x",
        secrets: [{ name: "", kind: "SECRET", origins: [], fieldTypes: [] }],
      }).ok,
    ).toBe(false);
    expect(
      validateTaskContract({
        task: "x",
        secrets: [{ name: "a", kind: "BOGUS", origins: [], fieldTypes: [] }],
      }).ok,
    ).toBe(false);
    expect(
      validateTaskContract({
        task: "x",
        secrets: [{ name: "a", kind: "SECRET", origins: "x", fieldTypes: [] }],
      }).ok,
    ).toBe(false);
    expect(
      validateTaskContract({
        task: "x",
        secrets: [{ name: "a", kind: "SECRET", origins: [], fieldTypes: "x" }],
      }).ok,
    ).toBe(false);
    expect(
      validateTaskContract({
        task: "x",
        secrets: [
          {
            name: "a",
            kind: "SECRET",
            origins: ["https://a.example/path"],
            fieldTypes: ["password"],
            unexpected: true,
          },
        ],
      }).ok,
    ).toBe(false);
    expect(
      validateTaskContract({
        task: "x",
        secrets: [
          {
            name: "a",
            kind: "SECRET",
            origins: ["https://a.example"],
            fieldTypes: ["Password With Spaces"],
            selector: "",
          },
        ],
      }).ok,
    ).toBe(false);
  });

  it("rejects malformed origins, budgets, and approval", () => {
    expect(validateTaskContract({ task: "x", origins: "nope" }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", origins: { allow: "x" } }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", origins: { bogus: [] } }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", budgets: "nope" }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", budgets: { maxActions: -1 } }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", budgets: { maxActions: "x" } }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", approval: "nope" }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", approval: { required: "yes" } }).ok).toBe(false);
    expect(validateTaskContract({ task: "x", approval: { timeoutMs: -5 } }).ok).toBe(false);
  });

  it("accepts a fully-populated contract", () => {
    const r = validateTaskContract({
      task: "t",
      capabilities: {
        navigation: "allowlist",
        downloads: true,
        uploads: true,
        purchases: true,
        messaging: true,
        destructiveActions: true,
        credentials: true,
        executeScript: true,
        privateNetwork: true,
        externalCommunication: true,
      },
      secrets: [
        { name: "a", kind: "CREDENTIAL", origins: ["https://a"], fieldTypes: ["password"] },
      ],
      origins: { allow: ["https://a"], block: ["https://b"] },
      budgets: {
        maxActions: 10,
        maxDurationMs: 1000,
        maxNavigations: 5,
        maxGuardCalls: 3,
        maxGuardTokens: 100,
      },
      approval: { required: true, timeoutMs: 500 },
    });
    expect(r.ok).toBe(true);
  });
});

describe("envelope navigation modes", () => {
  it("denies all navigation under mode none", () => {
    const env = compileTaskContract(contract({ task: "t", capabilities: { navigation: "none" } }));
    expect(
      env.evaluate({ type: "NAVIGATE", destination: "https://a", target: { origin: "https://a" } })
        .allowed,
    ).toBe(false);
  });

  it("allows same-origin and denies cross-origin", () => {
    const env = compileTaskContract(
      contract({ task: "t", capabilities: { navigation: "same-origin" } }),
    );
    expect(
      env.evaluate({
        type: "NAVIGATE",
        destination: "https://a/x",
        target: { origin: "https://a" },
      }).allowed,
    ).toBe(true);
    expect(
      env.evaluate({ type: "NAVIGATE", destination: "https://b", target: { origin: "https://a" } })
        .allowed,
    ).toBe(false);
  });

  it("allows same-site navigation", () => {
    const env = compileTaskContract(
      contract({ task: "t", capabilities: { navigation: "same-site" } }),
    );
    expect(
      env.evaluate({
        type: "NAVIGATE",
        destination: "https://a.example.com",
        target: { origin: "https://b.example.com" },
      }).allowed,
    ).toBe(true);
  });

  it("enforces the allowlist", () => {
    const env = compileTaskContract(
      contract({
        task: "t",
        capabilities: { navigation: "allowlist" },
        origins: { allow: ["https://a.example"] },
      }),
    );
    expect(
      env.evaluate({
        type: "NAVIGATE",
        destination: "https://a.example/x",
        target: { origin: "https://other" },
      }).allowed,
    ).toBe(true);
    expect(
      env.evaluate({
        type: "NAVIGATE",
        destination: "https://c.example",
        target: { origin: "https://other" },
      }).allowed,
    ).toBe(false);
  });

  it("narrows navigation and origins", () => {
    const env = compileTaskContract(
      contract({
        task: "t",
        capabilities: { navigation: "allowlist" },
        origins: { allow: ["https://a", "https://b"] },
      }),
    );
    expect(env.narrow({ navigation: "none" }).navigation).toBe("none");
    expect(env.narrow({ allowedOrigins: ["https://a"] }).allowedOrigins).toEqual(["https://a"]);
  });
});

describe("remaining runtime branches", () => {
  it("runWithDeadline rejects when the parent signal aborts", async () => {
    const controller = new AbortController();
    const p = runWithDeadline(
      (signal) =>
        new Promise<unknown>((_, reject) => {
          signal.addEventListener("abort", () => reject(new Error("aborted")));
        }),
      10_000,
      controller.signal,
    );
    controller.abort();
    const r = await p;
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.kind).toBe("cancelled");
    }
  });

  it("buildProbeScript uses defaults and custom caps", () => {
    expect(buildProbeScript()).toContain("2000");
    expect(buildProbeScript({ maxNodes: 5 })).toContain("5");
  });

  it("maxRiskState keeps the more restrictive state", () => {
    expect(maxRiskState("QUARANTINED", "NORMAL")).toBe("QUARANTINED");
    expect(maxRiskState("READ_ONLY", "READ_ONLY")).toBe("READ_ONLY");
  });

  it("sameSite compares IP hosts as equal only to themselves", () => {
    expect(sameSite("http://192.168.1.1", "http://192.168.1.1")).toBe(true);
    expect(sameSite("http://192.168.1.1", "http://192.168.1.2")).toBe(false);
  });
});
