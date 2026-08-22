import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  buildTrustedIntentContext,
  validateTrustedIntentContext,
  isTrustedIntent,
  wrapUntrustedContent,
  validateUntrustedContent,
  hash,
} from "../src/index.js";
import type { TrustedIntentContext, UntrustedContent } from "../src/index.js";

function validTrustedContext(overrides: Partial<TrustedIntentContext> = {}): TrustedIntentContext {
  return {
    task: "find a refundable hotel",
    action: {
      type: "NAVIGATE",
      destination: "https://hotel.example",
      instructionProvenance: { trust: "application" },
    },
    envelopeFacts: { navigationAllowed: true, uploadsAllowed: false },
    dataClassifications: ["none"],
    riskState: "NORMAL",
    provenance: { trust: "application", origin: "https://app.example" },
    priorActions: ["READ https://hotel.example"],
    ...overrides,
  };
}

describe("TrustedIntentContext isolation", () => {
  it("builds a deeply frozen, branded trusted context", () => {
    const ctx = buildTrustedIntentContext(validTrustedContext());
    expect(isTrustedIntent(ctx)).toBe(true);
    expect(Object.isFrozen(ctx)).toBe(true);
    expect(Object.isFrozen(ctx.envelopeFacts)).toBe(true);
    expect(Object.isFrozen(ctx.dataClassifications)).toBe(true);
    expect(Object.isFrozen(ctx.priorActions)).toBe(true);
    expect(() => {
      (ctx as unknown as { task: string }).task = "hacked";
    }).toThrow();
  });

  it("accepts a valid context and rejects unsafe provenance", () => {
    expect(validateTrustedIntentContext(validTrustedContext()).ok).toBe(true);
    const webProvenance = validateTrustedIntentContext(
      validTrustedContext({ provenance: { trust: "web" } }),
    );
    expect(webProvenance.ok).toBe(false);
    const memoryProvenance = validateTrustedIntentContext(
      validTrustedContext({ provenance: { trust: "memory" } }),
    );
    expect(memoryProvenance.ok).toBe(false);
  });

  it("rejects raw strings, observations, hostile fields, and unknown keys", () => {
    expect(validateTrustedIntentContext("raw").ok).toBe(false);
    expect(
      validateTrustedIntentContext({
        url: "https://x",
        origin: "https://x",
        frames: [],
        provenance: { trust: "web" },
      }).ok,
    ).toBe(false);
    expect(
      validateTrustedIntentContext(validTrustedContext({ screenshot: "data:image/png" } as never))
        .ok,
    ).toBe(false);
    expect(
      validateTrustedIntentContext(validTrustedContext({ manifest: { arbitrary: true } } as never))
        .ok,
    ).toBe(false);
    expect(
      validateTrustedIntentContext(
        validTrustedContext({ raw: "<script>alert(1)</script>" } as never),
      ).ok,
    ).toBe(false);
  });

  it("rejects oversized and malformed fields", () => {
    expect(validateTrustedIntentContext(validTrustedContext({ task: "" })).ok).toBe(false);
    expect(validateTrustedIntentContext(validTrustedContext({ task: "x".repeat(5000) })).ok).toBe(
      false,
    );
    expect(
      validateTrustedIntentContext(validTrustedContext({ riskState: "BOGUS" as never })).ok,
    ).toBe(false);
    expect(
      validateTrustedIntentContext(validTrustedContext({ action: { type: "NOPE" } as never })).ok,
    ).toBe(false);
    expect(
      validateTrustedIntentContext(validTrustedContext({ dataClassifications: ["x".repeat(100)] }))
        .ok,
    ).toBe(false);
  });

  it("never throws on arbitrary JSON-like input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateTrustedIntentContext(value)).not.toThrow();
      }),
    );
  });

  it("type-level: raw strings and page observations cannot reach the builder", () => {
    // @ts-expect-error — a raw string is not a TrustedIntentContext
    expect(() => buildTrustedIntentContext("raw")).toThrow();
    const observation = {
      url: "https://x",
      origin: "https://x",
      frames: [],
      provenance: { trust: "web" },
    };
    // @ts-expect-error — a PageObservation-like object is not a TrustedIntentContext
    expect(() => buildTrustedIntentContext(observation)).toThrow();
  });
});

describe("UntrustedContent isolation", () => {
  it("wraps sanitized content with provenance, hash, and instructionEligible false", () => {
    const wrapped = wrapUntrustedContent({
      content: "visible text",
      provenance: { trust: "web", origin: "https://x" },
    });
    expect(wrapped.instructionEligible).toBe(false);
    expect(wrapped.contentHash).toBe(hash("visible text"));
    expect(wrapped.provenance.trust).toBe("web");
    expect(wrapped.provenance.origin).toBe("https://x");
    expect(Object.isFrozen(wrapped)).toBe(true);
  });

  it("preserves provenance and hash across re-wrapping (deterministic)", () => {
    const a = wrapUntrustedContent({ content: "same", provenance: { trust: "tool" } });
    const b = wrapUntrustedContent({ content: "same", provenance: { trust: "tool" } });
    expect(a.contentHash).toBe(b.contentHash);
    expect(a.provenance.trust).toBe("tool");
  });

  it("rejects trusted provenance and instructionEligible true", () => {
    expect(() =>
      wrapUntrustedContent({ content: "x", provenance: { trust: "application" } }),
    ).toThrow();
    expect(() => wrapUntrustedContent({ content: "x", provenance: { trust: "user" } })).toThrow();
    expect(
      validateUntrustedContent({
        content: "x",
        provenance: { trust: "web" },
        contentHash: "h",
        revision: 0,
        truncated: false,
        instructionEligible: true,
      }),
    ).toBeNull();
    expect(
      validateUntrustedContent({
        content: "x",
        provenance: { trust: "web" },
        contentHash: "h",
        revision: 0,
        truncated: false,
        instructionEligible: false,
        extra: true,
      }),
    ).toBeNull();
  });

  it("type-level: instructionEligible is the literal false", () => {
    const wrapped: UntrustedContent = wrapUntrustedContent({
      content: "x",
      provenance: { trust: "web" },
    });
    const eligible: false = wrapped.instructionEligible;
    expect(eligible).toBe(false);
    // @ts-expect-error — instructionEligible can never be true
    const impossible: true = wrapped.instructionEligible;
    void impossible;
  });

  it("never throws on arbitrary JSON-like input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateUntrustedContent(value)).not.toThrow();
      }),
    );
  });
});

describe("schema agreement (isolation contracts vs published JSON Schemas)", () => {
  function loadSchema(name: string): Record<string, unknown> {
    const schemasDir = join(dirname(fileURLToPath(import.meta.url)), "..", "schemas");
    return JSON.parse(readFileSync(join(schemasDir, name), "utf8")) as Record<string, unknown>;
  }

  it("trusted-intent-context.schema.json is closed and matches the required set", () => {
    const schema = loadSchema("trusted-intent-context.schema.json");
    expect(schema["$id"]).toBe(
      "https://openagentfence.dev/schemas/trusted-intent-context.schema.json",
    );
    expect(schema["additionalProperties"]).toBe(false);
    expect(schema["required"]).toEqual([
      "task",
      "action",
      "envelopeFacts",
      "dataClassifications",
      "riskState",
      "provenance",
      "priorActions",
    ]);
    const provenance = (schema["properties"] as Record<string, unknown>)["provenance"] as Record<
      string,
      unknown
    >;
    const trust = (provenance["properties"] as Record<string, unknown>)["trust"] as Record<
      string,
      unknown
    >;
    expect(trust["enum"]).toEqual(["user", "application"]);
  });

  it("untrusted-content.schema.json is closed and pins instructionEligible to false", () => {
    const schema = loadSchema("untrusted-content.schema.json");
    expect(schema["$id"]).toBe("https://openagentfence.dev/schemas/untrusted-content.schema.json");
    expect(schema["additionalProperties"]).toBe(false);
    const instructionEligible = (schema["properties"] as Record<string, unknown>)[
      "instructionEligible"
    ] as Record<string, unknown>;
    expect(instructionEligible["const"]).toBe(false);
  });
});
