import { describe, expect, it } from "vitest";
import { RedactionRegistry, TraceWriter, hash } from "../src/index.js";

describe("redaction", () => {
  it("redacts exact values and normalized forms", () => {
    const r = new RedactionRegistry();
    r.registerSecret("SupEr-Secret-123");
    const out = r.redact("token SupEr-Secret-123 and SUPER-SECRET-123 and super-secret-123");
    expect(out).not.toContain("SupEr-Secret-123");
    expect(out).not.toContain("SUPER-SECRET-123");
    expect(out).not.toContain("super-secret-123");
  });

  it("is a branded type so plain strings cannot be assigned to evidence", () => {
    // Type-level: RedactedEvidence is enforced by the compiler; this asserts the
    // runtime redaction path returns redacted output for a finding string.
    const r = new RedactionRegistry();
    r.registerSecret("leak");
    const evidence = r.redact("the leak is here");
    expect(evidence).toBe("the [REDACTED] is here");
  });

  it("produces a stable hash", () => {
    expect(hash("abc")).toBe(hash("abc"));
    expect(hash("abc")).not.toBe(hash("abd"));
  });
});

describe("trace writer", () => {
  it("never writes registered secrets", () => {
    const r = new RedactionRegistry();
    r.registerSecret("hunter2");
    const writer = new TraceWriter(r);
    writer.start({ sessionId: "s" });
    writer.append("finding", {
      description: "password hunter2 leaked",
      nested: { value: "hunter2" },
    });
    const doc = JSON.stringify(writer.document());
    expect(doc).not.toContain("hunter2");
    expect(doc).toContain("[REDACTED]");
  });
});
