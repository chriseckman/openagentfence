import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  PolicyDocumentError,
  isValidatedPolicyDocument,
  loadPolicyDocument,
  parsePolicyDocumentSource,
} from "../../src/index.js";
import { propertyOptions } from "./config.js";

describe("OAF-TEST-013 policy parser and validator properties", () => {
  it("only returns a branded policy or a bounded typed error for arbitrary JSON", async () => {
    await fc.assert(
      fc.asyncProperty(fc.jsonValue(), async (value) => {
        try {
          const policy = await loadPolicyDocument(value as never);
          expect(isValidatedPolicyDocument(policy)).toBe(true);
          expect(Object.isFrozen(policy)).toBe(true);
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(PolicyDocumentError);
          if (error instanceof PolicyDocumentError) {
            expect(error.errors.length).toBeGreaterThan(0);
            expect(error.errors.length).toBeLessThanOrEqual(20);
          }
        }
        expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
      }),
      propertyOptions("policy.arbitrary-json"),
    );
  });

  it("only returns a branded policy or a bounded typed error for arbitrary YAML text", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 4_096 }), (source) => {
        try {
          const policy = parsePolicyDocumentSource(source, "property.yml");
          expect(isValidatedPolicyDocument(policy)).toBe(true);
          expect(Object.isFrozen(policy)).toBe(true);
        } catch (error: unknown) {
          expect(error).toBeInstanceOf(PolicyDocumentError);
          if (error instanceof PolicyDocumentError) {
            expect(error.errors.length).toBeGreaterThan(0);
            expect(error.errors.length).toBeLessThanOrEqual(20);
          }
        }
        expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
      }),
      propertyOptions("policy.arbitrary-yaml"),
    );
  });
});
