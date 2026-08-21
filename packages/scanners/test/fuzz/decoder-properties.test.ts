import fc from "fast-check";
import { describe, expect, it } from "vitest";
import counterexamples from "../fixtures/property-counterexamples.json" with { type: "json" };
import {
  decodeBase64,
  decodeHex,
  decodeIterative,
  decodeUnicodeEscapes,
  decodeUrlEncoded,
  fold,
} from "../../src/index.js";
import { propertyOptions } from "./config.js";

const TEST_LIMITS = {
  maxInputBytes: 512,
  maxDecodeDepth: 4,
  maxOutputBytes: 512,
  deadlineMs: 1_000,
} as const;

describe("OAF-TEST-013 decoder and normalizer properties", () => {
  it("never throws or exceeds documented iterative decode bounds", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 2_000 }), (input) => {
        const inputBytes = Buffer.byteLength(input, "utf8");
        const outcome = decodeIterative(input, TEST_LIMITS.maxDecodeDepth, 1_000, TEST_LIMITS);
        expect(outcome.chain.length).toBeLessThanOrEqual(TEST_LIMITS.maxDecodeDepth);
        if (inputBytes > TEST_LIMITS.maxInputBytes) {
          expect(outcome).toEqual({
            text: "",
            chain: [],
            status: "refused",
            reason: "input_too_large",
          });
        } else {
          expect(Buffer.byteLength(outcome.text, "utf8")).toBeLessThanOrEqual(
            TEST_LIMITS.maxOutputBytes,
          );
        }
        if (outcome.status === "refused") expect(outcome.reason).toBeDefined();
      }),
      propertyOptions("scanners.decoder-bounds"),
    );
  });

  it("round-trips every supported bounded reversible codec", () => {
    const printable = fc
      .array(fc.integer({ min: 32, max: 126 }), { minLength: 1, maxLength: 128 })
      .map((codes) => String.fromCodePoint(...codes));
    fc.assert(
      fc.property(printable, (input) => {
        const base64 = Buffer.from(input, "utf8").toString("base64");
        const hex = Buffer.from(input, "utf8").toString("hex");
        expect(decodeBase64(base64)).toBe(input);
        expect(decodeHex(hex)).toBe(input);
        expect(decodeUrlEncoded(encodeURIComponent(input))).toBe(input);
        const escaped = Array.from(
          input,
          (character) => `\\u${(character.codePointAt(0) ?? 32).toString(16).padStart(4, "0")}`,
        ).join("");
        expect(decodeUnicodeEscapes(escaped)).toBe(input);
      }),
      propertyOptions("scanners.decoder-roundtrip"),
    );
  });

  it("keeps minimized non-printable decoder counterexamples fail closed", () => {
    for (const regression of counterexamples.cases) {
      const input = String.fromCodePoint(...regression.inputCodePoints);
      expect(regression.expected).toBe("non_printable_refused");
      expect(decodeBase64(Buffer.from(input, "utf8").toString("base64"))).toBeNull();
      expect(decodeHex(Buffer.from(input, "utf8").toString("hex"))).toBeNull();
    }
  });

  it("normalizes arbitrary Unicode deterministically and idempotently", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 2_000 }), (input) => {
        const once = fold(input);
        const twice = fold(once);
        expect(twice).toBe(once);
        expect(Buffer.byteLength(once, "utf8")).toBeLessThanOrEqual(
          Math.max(8, Buffer.byteLength(input, "utf8") * 8),
        );
      }),
      propertyOptions("scanners.normalizer-idempotence"),
    );
  });
});
