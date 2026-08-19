import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  compileTaskContract,
  isValidatedTaskContract,
  secureDefaultEnvelope,
  validateTaskContract,
} from "../src/index.js";
import { NESTED_CONTRACT } from "./fixtures/contracts.js";

describe("validated contract immutability", () => {
  it("returns a deeply frozen, brand-marked contract", () => {
    const result = validateTaskContract(NESTED_CONTRACT);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const contract = result.value;
    expect(isValidatedTaskContract(contract)).toBe(true);
    expect(Object.isFrozen(contract)).toBe(true);
    expect(Object.isFrozen(contract.capabilities)).toBe(true);
    expect(Object.isFrozen(contract.secrets)).toBe(true);
    expect(Object.isFrozen(contract.secrets?.[0])).toBe(true);
    expect(Object.isFrozen(contract.secrets?.[0]?.origins)).toBe(true);
    expect(Object.isFrozen(contract.origins)).toBe(true);
    expect(Object.isFrozen(contract.origins?.allow)).toBe(true);
    expect(Object.isFrozen(contract.budgets)).toBe(true);
    expect(Object.isFrozen(contract.approval)).toBe(true);
  });

  it("rejects mutation at every nested level", () => {
    const result = validateTaskContract(NESTED_CONTRACT);
    if (!result.ok) {
      throw new Error("unexpected validation failure");
    }
    const contract = result.value;

    expect(() => {
      (contract as unknown as { task: string }).task = "hacked";
    }).toThrow();

    expect(contract.capabilities).toBeDefined();
    expect(() => {
      (contract.capabilities as unknown as { downloads: boolean }).downloads = true;
    }).toThrow();

    const secret = contract.secrets?.[0];
    expect(secret).toBeDefined();
    expect(() => {
      (secret as unknown as { name: string }).name = "hacked";
    }).toThrow();
    expect(() => {
      (secret as unknown as { origins: string[] }).origins.push("https://evil.example");
    }).toThrow();
  });
});

describe("envelope compiler boundary", () => {
  it("rejects a raw structural contract at runtime", () => {
    expect(() => compileTaskContract({ task: "raw" } as never)).toThrow();
    expect(() => compileTaskContract({} as never)).toThrow();
  });

  it("rejects page-supplied and provider-like objects", () => {
    expect(() => compileTaskContract({ task: "t", guard_model: "openai" } as never)).toThrow();
    expect(() => compileTaskContract({ capabilities: { uploads: true } } as never)).toThrow();
  });

  it("isValidatedTaskContract distinguishes validated from raw", () => {
    expect(isValidatedTaskContract({ task: "raw" })).toBe(false);
    expect(isValidatedTaskContract(null)).toBe(false);
    expect(isValidatedTaskContract("x")).toBe(false);
  });

  it("compiles a validated contract to an envelope", () => {
    const result = validateTaskContract(NESTED_CONTRACT);
    if (!result.ok) {
      throw new Error("unexpected validation failure");
    }
    const envelope = compileTaskContract(result.value);
    expect(envelope.task).toBe("find a refundable hotel");
    expect(envelope.downloads).toBe(true);
    expect(envelope.uploads).toBe(false);
    expect(envelope.navigation).toBe("allowlist");
  });

  it("type-level: a raw structural TaskContract cannot reach the compiler", () => {
    // @ts-expect-error — a raw TaskContract is not a ValidatedTaskContract
    expect(() => compileTaskContract({ task: "raw" })).toThrow();
  });
});

describe("secure defaults regression", () => {
  it("remains shrink-only and denies the default set", () => {
    const envelope = secureDefaultEnvelope("t");
    expect(envelope.evaluate({ type: "UPLOAD" }).allowed).toBe(false);
    expect(envelope.evaluate({ type: "PURCHASE" }).allowed).toBe(false);
    expect(envelope.evaluate({ type: "EXECUTE_SCRIPT" }).allowed).toBe(false);
    expect(envelope.evaluate({ type: "READ" }).allowed).toBe(true);

    fc.assert(
      fc.property(fc.boolean(), fc.boolean(), (a, b) => {
        const narrowed = envelope.narrow({ uploads: a, downloads: b });
        expect(narrowed.uploads).toBe(envelope.uploads && a);
        expect(narrowed.downloads).toBe(envelope.downloads && b);
      }),
    );
  });
});
