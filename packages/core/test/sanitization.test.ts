import { describe, expect, it } from "vitest";
import { applySanitizationPipeline, applySanitizationSpans } from "../src/index.js";

const provenance = {
  trust: "web" as const,
  pageId: "page-1",
  timestamp: "2026-01-01T00:00:00.000Z",
};

describe("span-level sanitization", () => {
  it("returns the base text when no spans are given", () => {
    expect(applySanitizationSpans("hello", [])).toBe("hello");
  });

  it("applies non-overlapping spans in order", () => {
    expect(
      applySanitizationSpans("abcdef", [
        { start: 0, end: 2, replacement: "XY", provenance },
        { start: 4, end: 6, replacement: "", provenance },
      ]),
    ).toBe("XYcd");
  });

  it("removal wins a full overlap", () => {
    expect(
      applySanitizationSpans("SECRET", [
        { start: 0, end: 6, replacement: "[REDACTED]", provenance },
        { start: 0, end: 6, replacement: "", provenance },
      ]),
    ).toBe("");
  });

  it("a replacement does not override a removal (reverse order)", () => {
    expect(
      applySanitizationSpans("SECRET", [
        { start: 0, end: 6, replacement: "", provenance },
        { start: 0, end: 6, replacement: "[REDACTED]", provenance },
      ]),
    ).toBe("");
  });

  it("removal dominates an overlapping replacement region", () => {
    expect(
      applySanitizationSpans("ABCDEFGH", [
        { start: 0, end: 4, replacement: "XXXX", provenance },
        { start: 2, end: 6, replacement: "", provenance },
      ]),
    ).toBe("ABGH");
  });

  it("clamps out-of-range offsets safely", () => {
    expect(
      applySanitizationSpans("abc", [{ start: 0, end: 99, replacement: "", provenance }]),
    ).toBe("");
    expect(
      applySanitizationSpans("abc", [{ start: -5, end: 1, replacement: "", provenance }]),
    ).toBe("bc");
  });

  it("does not let a whole-text sanitizer restore a span-sanitized value", () => {
    const detected = `AKIA${"A".repeat(16)}`;
    const base = `visible ${detected} text`;
    const start = base.indexOf("AKIA");
    expect(
      applySanitizationPipeline(
        base,
        [
          {
            start,
            end: start + detected.length,
            replacement: "<SECRET:detected:opaque>",
            provenance,
          },
        ],
        [{ value: base, provenance }],
      ),
    ).toBe("visible <SECRET:detected:opaque> text");
  });
});
