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

  it("redacts URI, base64url, and Unicode-normalized representations", () => {
    const r = new RedactionRegistry();
    r.registerSecret("S\u00e9cret value");
    const encoded = encodeURIComponent("S\u00e9cret value");
    const base64url = Buffer.from("S\u00e9cret value", "utf8")
      .toString("base64")
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/, "");
    const decomposed = "Se\u0301cret value";
    const out = r.redact(`${encoded} ${base64url} ${decomposed}`);
    expect(r.containsSecret(encoded)).toBe(true);
    expect(out).not.toContain(encoded);
    expect(out).not.toContain(base64url);
    expect(out).not.toContain(decomposed);
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

  it("redacts registered values from provenance metadata before trace emission", () => {
    const sentinel = "synthetic-provider-credential-123";
    const r = new RedactionRegistry();
    r.registerSecret(sentinel);
    const writer = new TraceWriter(r);
    writer.start({ sessionId: "s" });
    writer.append("finding", {
      provenance: {
        trust: "web",
        origin: `https://${sentinel}.example`,
        frameOrigin: `https://frame.example/${sentinel}`,
        pageId: `page-${sentinel}`,
        elementId: `#node-${sentinel}`,
      },
    });
    const serialized = JSON.stringify(writer.document());
    expect(serialized).not.toContain(sentinel);
    expect(serialized).toContain("[REDACTED]");
  });

  it("bounds registered values and makes egress matching non-clean after exhaustion", () => {
    const registry = new RedactionRegistry({ maxValues: 1, maxTotalFormBytes: 4096 });
    expect(registry.registerSecret("first-synthetic-value")).toBe(true);
    expect(registry.registerSecret("second-synthetic-value")).toBe(false);
    expect(registry.incomplete).toBe(true);
    expect(registry.matchEgress("first-synthetic-value").incomplete).toBe(true);
    registry.clear();
    expect(registry.incomplete).toBe(false);
    expect(registry.secretFingerprints()).toEqual([]);
  });

  it("bounds cyclic and deeply nested trace data", () => {
    const writer = new TraceWriter(new RedactionRegistry());
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    let deep: unknown = "leaf";
    for (let i = 0; i < 20; i += 1) deep = { deep };
    writer.start({ sessionId: "s" });
    writer.append("finding", { cyclic, deep });
    const serialized = JSON.stringify(writer.document());
    expect(serialized).toContain("[REDACTED:CYCLE]");
    expect(serialized).toContain("[REDACTED:DEPTH]");
  });
});
