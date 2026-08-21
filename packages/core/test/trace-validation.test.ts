import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  TRACE_SCHEMA_VERSION,
  validateTraceEvent,
  validateTraceDocument,
  isCompatibleSchemaVersion,
  schemaVersionMajor,
} from "../src/index.js";

function event(
  kind: string,
  data: Record<string, unknown>,
  timestamp = "2026-08-16T00:00:00.000Z",
) {
  return { kind, timestamp, data };
}

function validStart(overrides: Record<string, unknown> = {}) {
  return event("session_start", {
    sessionId: "s1",
    task: "read a page",
    policyHash: "abc123",
    capabilities: {
      route: false,
      downloadEvents: false,
      popupEvents: false,
      screenshot: false,
      ariaSnapshot: false,
    },
    versions: { schema: TRACE_SCHEMA_VERSION, core: "0.0.0" },
    ...overrides,
  });
}

function validEnd(overrides: Record<string, unknown> = {}) {
  return event("session_end", { risk: "NORMAL", score: 0, ...overrides });
}

describe("trace event validation", () => {
  it("accepts a well-formed event of every kind", () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["session_start", { sessionId: "s", policyHash: "h", versions: { schema: "1.0.0" } }],
      [
        "observation",
        {
          url: "https://a.example",
          origin: "https://a.example",
          provenance: { trust: "web", timestamp: "2026-01-01T00:00:00.000Z" },
        },
      ],
      [
        "taint_activation",
        {
          source: "observation",
          provenance: { trust: "web", timestamp: "2026-01-01T00:00:00.000Z" },
        },
      ],
      [
        "trusted_instruction_claim",
        {
          instructedBy: "user",
          actionType: "NAVIGATE",
          instructionProvenance: { trust: "user", timestamp: "2026-01-01T00:00:00.000Z" },
        },
      ],
      [
        "finding",
        {
          id: "f1",
          category: "c",
          sourceType: "dom",
          evidenceHash: "e",
          provenance: { trust: "web", timestamp: "2026-01-01T00:00:00.000Z" },
        },
      ],
      ["scan_result", { scanner: "x", failureKind: "timeout" }],
      ["proposed_action", { type: "NAVIGATE", instructionProvenance: { trust: "application" } }],
      ["canonical_action", { type: "NAVIGATE", instructionProvenance: { trust: "application" } }],
      [
        "policy_decision",
        { verdict: "BLOCK", reasons: ["destination_not_allowed"], policyHash: "h" },
      ],
      ["approval_request", { id: "a1", actionType: "PURCHASE", risk: "NORMAL" }],
      ["approval_decision", { id: "a1", approved: false, scope: "once" }],
      ["execution", { type: "NAVIGATE" }],
      ["post_action", { ok: true }],
      ["risk_change", { state: "RESTRICTED", score: 40 }],
      ["budget_event", { budget: "actions", remaining: 10 }],
      ["escape_hatch", { reason: "testing" }],
      [
        "secret_resolution",
        {
          handleFingerprint: "handle-hash",
          sinkFingerprint: "sink-hash",
          outcome: "denied",
          reason: "secret_sink_not_allowed",
        },
      ],
      [
        "egress_inspection",
        {
          sink: "routed_request_body",
          verdict: "block",
          inspectedBytes: 32,
          matchCount: 1,
          reasons: ["sensitive_value_in_egress"],
        },
      ],
      [
        "memory_write",
        {
          allowed: true,
          contentHash: "a".repeat(64),
          sensitivity: "sensitive",
          markers: ["instruction_removed"],
          provenance: { trust: "web", origin: "https://a.example" },
        },
      ],
      [
        "memory_read",
        {
          allowed: true,
          contentHash: "a".repeat(64),
          sensitivity: "sensitive",
          markers: ["instruction_removed"],
          storedProvenance: { trust: "web", origin: "https://a.example" },
          releasedProvenance: { trust: "memory", origin: "https://a.example" },
        },
      ],
      ["session_end", { risk: "NORMAL", score: 0 }],
    ];
    for (const [kind, data] of cases) {
      const result = validateTraceEvent(event(kind, data));
      expect(result.ok, `${kind}: ${result.errors.join("; ")}`).toBe(true);
    }
  });

  it("rejects malformed events", () => {
    expect(validateTraceEvent("nope").ok).toBe(false);
    expect(validateTraceEvent(event("bogus", {})).ok).toBe(false);
    expect(validateTraceEvent({ kind: "finding", timestamp: "", data: {} }).ok).toBe(false);
    expect(validateTraceEvent({ kind: "finding", timestamp: "t", data: "x" }).ok).toBe(false);
    expect(
      validateTraceEvent(
        event("egress_inspection", {
          sink: "unknown",
          verdict: "allow",
          inspectedBytes: -1,
          matchCount: 0,
        }),
      ).ok,
    ).toBe(false);
    expect(validateTraceEvent(event("memory_write", { allowed: false })).ok).toBe(false);
    expect(validateTraceEvent(event("memory_read", { allowed: true })).ok).toBe(false);
    expect(
      validateTraceEvent(
        event("egress_inspection", {
          sink: "message",
          verdict: "block",
          inspectedBytes: 8,
          matchCount: 1,
          sources: [{ fingerprint: "not-sha256", provenance: { trust: "web" } }],
        }),
      ).ok,
    ).toBe(false);
  });

  it("rejects session_start missing trusted metadata", () => {
    expect(validateTraceEvent(event("session_start", {})).ok).toBe(false);
    expect(validateTraceEvent(event("session_start", { sessionId: "s" })).ok).toBe(false);
    expect(validateTraceEvent(event("session_start", { sessionId: "s", policyHash: "h" })).ok).toBe(
      false,
    );
  });

  it("rejects a finding without an evidence hash", () => {
    expect(validateTraceEvent(event("finding", { id: "f1" })).ok).toBe(false);
  });

  it("rejects provenance-free security trace events", () => {
    expect(
      validateTraceEvent(
        event("observation", { url: "https://a.example", origin: "https://a.example" }),
      ).ok,
    ).toBe(false);
    expect(validateTraceEvent(event("finding", { id: "f1", evidenceHash: "e" })).ok).toBe(false);
    expect(validateTraceEvent(event("canonical_action", { type: "FILL" })).ok).toBe(false);
    expect(validateTraceEvent(event("taint_activation", { source: "observation" })).ok).toBe(false);
    expect(
      validateTraceEvent(
        event("trusted_instruction_claim", { instructedBy: "user", actionType: "CLICK" }),
      ).ok,
    ).toBe(false);
  });

  it("rejects policy decisions that are not explainable or carry bad evidence", () => {
    expect(validateTraceEvent(event("policy_decision", { verdict: "BLOCK" })).ok).toBe(false);
    expect(validateTraceEvent(event("policy_decision", { verdict: "BLOCK", reasons: [] })).ok).toBe(
      false,
    );
    expect(
      validateTraceEvent(event("policy_decision", { verdict: "NOPE", reasons: ["x"] })).ok,
    ).toBe(false);
    expect(
      validateTraceEvent(
        event("policy_decision", { verdict: "BLOCK", reasons: ["x"], evidence: [{}] }),
      ).ok,
    ).toBe(false);
    expect(
      validateTraceEvent(
        event("policy_decision", {
          verdict: "BLOCK",
          reasons: ["x"],
          evidence: [{ findingId: "f", category: "c", evidenceHash: "e", sourceType: "dom" }],
        }),
      ).ok,
    ).toBe(true);
  });

  it("rejects approval and escape-hatch events with missing required fields", () => {
    expect(validateTraceEvent(event("approval_request", {})).ok).toBe(false);
    expect(validateTraceEvent(event("approval_decision", { id: "a" })).ok).toBe(false);
    expect(validateTraceEvent(event("escape_hatch", { reason: "" })).ok).toBe(false);
    expect(validateTraceEvent(event("risk_change", { state: "" })).ok).toBe(false);
    expect(
      validateTraceEvent(
        event("secret_resolution", {
          handleFingerprint: "h",
          sinkFingerprint: "s",
          outcome: "denied",
          reason: "free-form-reason",
        }),
      ).ok,
    ).toBe(false);
  });
});

describe("trace document validation", () => {
  it("accepts a representative lifecycle trace", () => {
    const doc = {
      schemaVersion: TRACE_SCHEMA_VERSION,
      events: [
        validStart(),
        event("observation", {
          url: "https://a.example",
          origin: "https://a.example",
          provenance: { trust: "web", timestamp: "2026-01-01T00:00:00.000Z" },
        }),
        event("finding", {
          id: "f1",
          category: "hidden_dom_instruction",
          sourceType: "dom",
          evidenceHash: "e",
          provenance: { trust: "web", timestamp: "2026-01-01T00:00:00.000Z" },
        }),
        event("policy_decision", {
          verdict: "BLOCK",
          reasons: ["destination_not_allowed", "session_restricted"],
          policyHash: "h",
          evidence: [
            {
              findingId: "f1",
              category: "hidden_dom_instruction",
              evidenceHash: "e",
              sourceType: "dom",
            },
          ],
        }),
        event("escape_hatch", { reason: "testing" }),
        validEnd(),
      ],
    };
    expect(validateTraceDocument(doc).ok).toBe(true);
  });

  it("rejects an incompatible schema major", () => {
    const doc = {
      schemaVersion: "2.0.0",
      events: [validStart(), validEnd()],
    };
    const result = validateTraceDocument(doc);
    expect(result.ok).toBe(false);
    expect(result.errors.join(" ")).toContain("incompatible");
  });

  it("rejects a non-semver schemaVersion", () => {
    expect(validateTraceDocument({ schemaVersion: "one", events: [] }).ok).toBe(false);
  });

  it("rejects missing events array", () => {
    expect(validateTraceDocument({ schemaVersion: TRACE_SCHEMA_VERSION }).ok).toBe(false);
  });

  it("rejects ordering violations", () => {
    expect(
      validateTraceDocument({
        schemaVersion: TRACE_SCHEMA_VERSION,
        events: [event("observation", { url: "u", origin: "o" })],
      }).ok,
    ).toBe(false);
    expect(
      validateTraceDocument({
        schemaVersion: TRACE_SCHEMA_VERSION,
        events: [validStart(), validEnd(), event("risk_change", { state: "NORMAL" })],
      }).ok,
    ).toBe(false);
  });

  it("rejects malformed events inside a document", () => {
    expect(
      validateTraceDocument({
        schemaVersion: TRACE_SCHEMA_VERSION,
        events: [validStart(), event("finding", { id: "" }), validEnd()],
      }).ok,
    ).toBe(false);
  });

  it("never throws on arbitrary JSON-like input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateTraceDocument(value)).not.toThrow();
      }),
    );
  });
});

describe("schema version compatibility", () => {
  it("parses semver majors", () => {
    expect(schemaVersionMajor("1.2.3")).toBe(1);
    expect(schemaVersionMajor("not-semver")).toBeNull();
    expect(schemaVersionMajor("10.0.0")).toBe(10);
  });

  it("accepts the same major, rejects others", () => {
    expect(isCompatibleSchemaVersion("1.0.0")).toBe(true);
    expect(isCompatibleSchemaVersion("1.99.0")).toBe(true);
    expect(isCompatibleSchemaVersion("2.0.0")).toBe(false);
    expect(isCompatibleSchemaVersion("0.9.0")).toBe(false);
  });
});

describe("schema agreement (trace validator vs published JSON Schema)", () => {
  function loadSchema(): Record<string, unknown> {
    const schemasDir = join(dirname(fileURLToPath(import.meta.url)), "..", "schemas");
    return JSON.parse(readFileSync(join(schemasDir, "trace.schema.json"), "utf8")) as Record<
      string,
      unknown
    >;
  }

  it("has a stable id, closed top-level object, and the same event kinds", () => {
    const schema = loadSchema();
    expect(schema["$id"]).toBe("https://openagentfence.dev/schemas/trace.schema.json");
    expect(schema["additionalProperties"]).toBe(false);
    expect(schema["required"]).toEqual(["schemaVersion", "events"]);
    const defs = schema["$defs"] as Record<string, unknown>;
    const traceEvent = defs["traceEvent"] as Record<string, unknown>;
    const kindEnum = (traceEvent["properties"] as Record<string, unknown>)["kind"] as Record<
      string,
      unknown
    >;
    const kinds = kindEnum["enum"] as string[];
    expect(kinds).toContain("session_start");
    expect(kinds).toContain("session_end");
    expect(kinds).toContain("policy_decision");
    expect(kinds).toContain("escape_hatch");
    expect(kinds).toContain("taint_activation");
    expect(kinds).toContain("trusted_instruction_claim");
    expect(kinds).toContain("egress_inspection");
  });
});
