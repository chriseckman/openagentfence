import { describe, expect, it } from "vitest";
import {
  createSecretSensitiveScanner,
  secretPatternsFromPolicy,
  validateSecretPattern,
} from "../src/index.js";
import { node, probe, scannerContext } from "./helpers.js";

const SYNTHETIC_AWS = `AKIA${"A".repeat(16)}`;
const SYNTHETIC_GITHUB = `ghp_${"B".repeat(36)}`;

describe("bounded secret-sensitive scanner", () => {
  it("detects supported synthetic classes with value-free evidence and replacement markers", async () => {
    const raw = `keys ${SYNTHETIC_AWS} and password=syntheticPassword123`;
    const result = await createSecretSensitiveScanner().scan(
      scannerContext(probe([node({ text: raw })])),
    );
    expect(result.verdict).toBe("sanitize");
    expect(result.sanitizations).toHaveLength(2);
    expect(JSON.stringify(result.findings)).not.toContain(SYNTHETIC_AWS);
    expect(JSON.stringify(result.findings)).not.toContain("syntheticPassword123");
    expect(result.findings.every((finding) => finding.provenance.trust === "web")).toBe(true);
  });

  it("leaves documented benign look-alikes unmodified", async () => {
    const raw = "AKIA-short password=changeme api_key=example";
    const result = await createSecretSensitiveScanner().scan(
      scannerContext(probe([node({ text: raw })])),
    );
    expect(result.verdict).toBe("allow");
    expect(result.sanitizations).toBeUndefined();
  });

  it("fails closed for oversized and cancelled input", async () => {
    const oversized = scannerContext(probe([node({ text: "x".repeat(102_401) })]));
    const oversizedResult = await createSecretSensitiveScanner().scan(oversized);
    expect(oversizedResult.sanitized?.value).toBe("[REDACTED:SENSITIVE_SCAN_INCOMPLETE]");

    const controller = new AbortController();
    controller.abort();
    const cancelledResult = await createSecretSensitiveScanner().scan({
      ...scannerContext(probe([node({ text: SYNTHETIC_GITHUB })])),
      signal: controller.signal,
    });
    expect(cancelledResult.verdict).toBe("sanitize");
    expect(cancelledResult.metadata?.["failureKind"]).toBe("cancelled");
  });

  it("accepts only bounded data-only custom patterns", async () => {
    const custom = validateSecretPattern({
      id: "vendor_key",
      prefix: "vendor_",
      alphabet: "base64url",
      minLength: 20,
      maxLength: 24,
    });
    const result = await createSecretSensitiveScanner([custom]).scan(
      scannerContext(probe([node({ text: `vendor_${"z".repeat(13)}` })])),
    );
    expect(result.verdict).toBe("sanitize");
    expect(() =>
      validateSecretPattern({
        id: "unsafe",
        prefix: "(a+)+$",
        alphabet: "alphanumeric",
        minLength: 7,
        maxLength: 8,
      }),
    ).toThrow();
    expect(() => createSecretSensitiveScanner(new Array(33).fill(custom))).toThrow("too many");
  });

  it("converts validated policy-document patterns", () => {
    expect(
      secretPatternsFromPolicy([
        {
          id: "vendor_token",
          prefix: "vend_",
          alphabet: "base64url",
          min_length: 24,
          max_length: 64,
          kind: "CREDENTIAL",
        },
      ]),
    ).toEqual([
      {
        id: "vendor_token",
        prefix: "vend_",
        alphabet: "base64url",
        minLength: 24,
        maxLength: 64,
        kind: "CREDENTIAL",
      },
    ]);
  });
});
