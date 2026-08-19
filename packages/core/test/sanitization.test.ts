import { describe, expect, it } from "vitest";
import { applySanitizationSpans } from "../src/index.js";

describe("span-level sanitization", () => {
  it("returns the base text when no spans are given", () => {
    expect(applySanitizationSpans("hello", [])).toBe("hello");
  });

  it("applies non-overlapping spans in order", () => {
    expect(
      applySanitizationSpans("abcdef", [
        { start: 0, end: 2, replacement: "XY" },
        { start: 4, end: 6, replacement: "" },
      ]),
    ).toBe("XYcd");
  });

  it("removal wins a full overlap", () => {
    expect(
      applySanitizationSpans("SECRET", [
        { start: 0, end: 6, replacement: "[REDACTED]" },
        { start: 0, end: 6, replacement: "" },
      ]),
    ).toBe("");
  });

  it("a replacement does not override a removal (reverse order)", () => {
    expect(
      applySanitizationSpans("SECRET", [
        { start: 0, end: 6, replacement: "" },
        { start: 0, end: 6, replacement: "[REDACTED]" },
      ]),
    ).toBe("");
  });

  it("removal dominates an overlapping replacement region", () => {
    expect(
      applySanitizationSpans("ABCDEFGH", [
        { start: 0, end: 4, replacement: "XXXX" },
        { start: 2, end: 6, replacement: "" },
      ]),
    ).toBe("ABGH");
  });

  it("clamps out-of-range offsets safely", () => {
    expect(applySanitizationSpans("abc", [{ start: 0, end: 99, replacement: "" }])).toBe("");
    expect(applySanitizationSpans("abc", [{ start: -5, end: 1, replacement: "" }])).toBe("bc");
  });
});
