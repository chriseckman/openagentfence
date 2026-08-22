import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { validateFinding, validateScanResult } from "../src/index.js";
import {
  VALID_FINDINGS,
  INVALID_FINDINGS,
  VALID_SCAN_RESULTS,
  INVALID_SCAN_RESULTS,
} from "./fixtures/results.js";

function loadSchema(name: string): Record<string, unknown> {
  const schemasDir = join(dirname(fileURLToPath(import.meta.url)), "..", "schemas");
  return JSON.parse(readFileSync(join(schemasDir, name), "utf8")) as Record<string, unknown>;
}

describe("Finding runtime validator", () => {
  it("accepts every valid fixture", () => {
    for (const fixture of VALID_FINDINGS) {
      expect(validateFinding(fixture), JSON.stringify(fixture)).not.toBeNull();
    }
  });

  it("rejects every invalid fixture", () => {
    for (const fixture of INVALID_FINDINGS) {
      expect(validateFinding(fixture), JSON.stringify(fixture)).toBeNull();
    }
  });

  it("never throws on arbitrary JSON-like input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateFinding(value)).not.toThrow();
      }),
    );
  });
});

describe("ScanResult runtime validator", () => {
  it("accepts every valid fixture", () => {
    for (const fixture of VALID_SCAN_RESULTS) {
      expect(validateScanResult(fixture), JSON.stringify(fixture)).not.toBeNull();
    }
  });

  it("rejects every invalid fixture", () => {
    for (const fixture of INVALID_SCAN_RESULTS) {
      expect(validateScanResult(fixture), JSON.stringify(fixture)).toBeNull();
    }
  });

  it("never throws on arbitrary JSON-like input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateScanResult(value)).not.toThrow();
      }),
    );
  });
});

describe("schema agreement (runtime validator vs published JSON Schema)", () => {
  it("finding.schema.json has a stable id, closed objects, and the validator's field set", () => {
    const schema = loadSchema("finding.schema.json");
    expect(schema["$id"]).toBe("https://openagentfence.dev/schemas/finding.schema.json");
    expect(schema["additionalProperties"]).toBe(false);
    expect(schema["required"]).toEqual([
      "id",
      "category",
      "title",
      "description",
      "source",
      "provenance",
      "evidence",
      "recommendedAction",
    ]);
    const props = schema["properties"] as Record<string, unknown>;
    expect(Object.keys(props).sort()).toEqual(
      [
        "id",
        "category",
        "title",
        "description",
        "source",
        "provenance",
        "evidence",
        "recommendedAction",
        "severity",
        "confidence",
      ].sort(),
    );
    const source = props["source"] as Record<string, unknown>;
    expect(source["additionalProperties"]).toBe(false);
    const provenance = props["provenance"] as Record<string, unknown>;
    expect(provenance["additionalProperties"]).toBe(false);
    const box = (source["properties"] as Record<string, unknown>)["boundingBox"] as Record<
      string,
      unknown
    >;
    expect(box["additionalProperties"]).toBe(false);
  });

  it("scan-result.schema.json has a stable id, closed object, and the validator's field set", () => {
    const schema = loadSchema("scan-result.schema.json");
    expect(schema["$id"]).toBe("https://openagentfence.dev/schemas/scan-result.schema.json");
    expect(schema["additionalProperties"]).toBe(false);
    expect(schema["required"]).toEqual(["scanner", "kind", "verdict", "severity", "findings"]);
    const props = schema["properties"] as Record<string, unknown>;
    expect(Object.keys(props).sort()).toEqual(
      [
        "scanner",
        "kind",
        "verdict",
        "severity",
        "confidence",
        "findings",
        "sanitized",
        "sanitizations",
        "timedOut",
        "metadata",
      ].sort(),
    );
  });
});
