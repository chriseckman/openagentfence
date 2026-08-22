import { describe, expect, it } from "vitest";
import { validateGuardClassification } from "../src/index.js";

describe("guard classification validation", () => {
  it("accepts a valid response", () => {
    const c = validateGuardClassification({
      promptInjection: true,
      confidence: 0.9,
      categories: ["instruction_override"],
      recommendedVerdict: "block",
    });
    expect(c).not.toBeNull();
    expect(c?.promptInjection).toBe(true);
  });

  it("rejects out-of-range confidence", () => {
    expect(
      validateGuardClassification({
        promptInjection: false,
        confidence: 2,
        categories: [],
        recommendedVerdict: "allow",
      }),
    ).toBeNull();
  });

  it("rejects a non-boolean promptInjection", () => {
    expect(
      validateGuardClassification({
        promptInjection: "yes",
        confidence: 0.5,
        categories: [],
        recommendedVerdict: "warn",
      }),
    ).toBeNull();
  });

  it("rejects an invalid recommended verdict", () => {
    expect(
      validateGuardClassification({
        promptInjection: false,
        confidence: 0.5,
        categories: [],
        recommendedVerdict: "BLOCK",
      }),
    ).toBeNull();
  });
});
