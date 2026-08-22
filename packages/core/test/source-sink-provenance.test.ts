import { describe, expect, it, vi } from "vitest";
import fc from "fast-check";
import {
  OpenAgentFence,
  REASON_CODES,
  SourceValueRegistry,
  createSourceSinkCheck,
  defineScanner,
  egressMatchForms,
  hash,
  type EgressPayload,
  type PolicyEngine,
} from "../src/index.js";
import { fakeAdapter, mkAction } from "./helpers.js";

const SOURCE = "https://source.example";
const OTHER = "https://other.example";
const VALUE = "Synthetic.Person+M6@example.test";
const provenance = {
  trust: "web" as const,
  origin: SOURCE,
  frameOrigin: SOURCE,
  pageId: "page-a",
  elementId: "pii-node",
  timestamp: "2026-08-20T00:00:00.000Z",
};

describe("bounded source-to-sink provenance registry", () => {
  it("property-matches every documented normalization without exposing the raw value", () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[A-Za-z0-9]{16,48}$/),
        fc.constantFrom("exact", "trimmed", "lower", "upper", "url", "base64"),
        (value, representation) => {
          const registry = new SourceValueRegistry();
          expect(registry.register(value, provenance)).toBe("registered");
          const forms = egressMatchForms(value);
          const selected =
            representation === "trimmed"
              ? ` ${value} `
              : representation === "lower"
                ? value.toLowerCase()
                : representation === "upper"
                  ? value.toUpperCase()
                  : representation === "url"
                    ? encodeURIComponent(value)
                    : representation === "base64"
                      ? Buffer.from(value, "utf8").toString("base64")
                      : value;
          expect(forms).toContain(selected.trim() === value ? value : selected);
          const match = registry.match(`prefix:${selected}:suffix`);
          expect(match.incomplete).toBe(false);
          expect(match.fingerprints).toEqual([hash(value)]);
          expect(match.sources).toEqual([{ fingerprint: hash(value), provenance }]);
          expect(Object.keys(match.sources[0] ?? {})).toEqual(["fingerprint", "provenance"]);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("preserves provenance across D-11 matching and expires entries", () => {
    let now = 1_000;
    const registry = new SourceValueRegistry(
      {
        maxEntries: 2,
        maxProvenancesPerEntry: 2,
        maxMatchedSources: 4,
        maxTotalFormBytes: 16_384,
        maxValueBytes: 4096,
        ttlMs: 50,
      },
      () => now,
    );
    expect(registry.register(VALUE, provenance)).toBe("registered");
    for (const form of egressMatchForms(VALUE)) {
      const match = registry.match(`prefix:${form}:suffix`);
      expect(match.incomplete).toBe(false);
      expect(match.fingerprints).toEqual([hash(VALUE)]);
      expect(match.sources).toEqual([{ fingerprint: hash(VALUE), provenance }]);
      expect(JSON.stringify(match)).not.toContain(VALUE);
    }
    now += 51;
    expect(registry.match(VALUE)).toEqual({ fingerprints: [], sources: [], incomplete: false });
    expect(registry.size).toBe(0);
  });

  it("fails non-clean on capacity, evidence, byte, and cancellation bounds", () => {
    const limits = {
      maxEntries: 1,
      maxProvenancesPerEntry: 1,
      maxMatchedSources: 1,
      maxTotalFormBytes: 1024,
      maxValueBytes: 64,
      ttlMs: 1000,
    };
    const registry = new SourceValueRegistry(limits, () => 0);
    expect(registry.register("first-value", provenance)).toBe("registered");
    expect(registry.register("second-value", provenance)).toBe("incomplete");
    expect(registry.match("first-value").incomplete).toBe(true);

    const check = createSourceSinkCheck({
      isDestinationAllowed: () => false,
      limits,
      now: () => 0,
    });
    expect(check.register({ value: "x".repeat(65), provenance })).toBe("incomplete");
    expect(check.inspect(payload("safe", OTHER))).toMatchObject({
      verdict: "block",
      reasons: [REASON_CODES.egress_inspection_incomplete],
    });

    const cancelled = new AbortController();
    cancelled.abort();
    const cancelledCheck = createSourceSinkCheck({
      isDestinationAllowed: () => false,
      limits,
      now: () => 0,
    });
    expect(cancelledCheck.register({ value: "value", provenance }, cancelled.signal)).toBe(
      "incomplete",
    );
    expect(cancelledCheck.inspect(payload("value", OTHER), cancelled.signal).verdict).toBe("block");
  });

  it("blocks detected page-A data at unrelated B before semantic scanning but allows A", async () => {
    const fakeSafe = vi.fn(async () => ({
      scanner: "fake-safe",
      kind: "semantic" as const,
      verdict: "allow" as const,
      severity: "info" as const,
      findings: [],
    }));
    const detector = defineScanner({
      id: "synthetic-pii",
      phases: ["PERCEPTION", "EGRESS"],
      kind: "deterministic",
      scan: async (ctx) => {
        const text =
          ctx.payload.kind === "observation"
            ? (ctx.payload.observation.ariaSnapshot ?? "")
            : ctx.payload.kind === "egressPayload" && typeof ctx.payload.payload.value === "string"
              ? ctx.payload.payload.value
              : "";
        const start = text.indexOf(VALUE);
        return {
          scanner: "synthetic-pii",
          kind: "deterministic" as const,
          verdict: start < 0 ? ("allow" as const) : ("sanitize" as const),
          severity: start < 0 ? ("info" as const) : ("high" as const),
          findings: [],
          ...(start < 0
            ? {}
            : {
                sanitizations: [
                  {
                    start,
                    end: start + VALUE.length,
                    replacement: "[[OAF_SENSITIVE:PII:synthetic_email]]",
                    provenance,
                  },
                ],
              }),
        };
      },
    });
    const semantic = defineScanner({
      id: "fake-safe",
      phases: ["PRE_ACTION"],
      kind: "semantic",
      scan: fakeSafe,
    });
    const session = new OpenAgentFence({
      adapter: fakeAdapter({
        observe: async () => ({
          url: `${SOURCE}/a`,
          origin: SOURCE,
          frames: [],
          ariaSnapshot: `Account ${VALUE}`,
          provenance,
        }),
      }),
      scanners: [detector, semantic],
      policy: allowPolicy,
    }).start({
      task: "return account data only to its source",
      capabilities: { messaging: true, externalCommunication: true },
      origins: { allow: [SOURCE, OTHER] },
    });

    const observed = await session.observe();
    expect(observed.sanitizedText.value).not.toContain(VALUE);
    const sameOrigin = await session.authorize(
      mkAction("MESSAGE", { destination: `${SOURCE}/reply`, data: VALUE }),
    );
    expect(sameOrigin.verdict).toBe("ALLOW");

    const blocked = await session.authorize(
      mkAction("MESSAGE", { destination: `${OTHER}/collect`, data: VALUE }),
    );
    expect(blocked.verdict).toBe("BLOCK");
    expect(blocked.reasons).toContain(REASON_CODES.sensitive_value_in_egress);
    expect(blocked.reasons).toContain(REASON_CODES.untrusted_cross_origin_egress);
    expect(fakeSafe).toHaveBeenCalledTimes(1);
    const trace = await session.end();
    const serialized = JSON.stringify(trace);
    expect(serialized).not.toContain(VALUE);
    expect(serialized).toContain(hash(VALUE));
    expect(serialized).toContain('"pageId":"page-a"');
  });
});

const allowPolicy: PolicyEngine = {
  policyHash: "source-sink",
  evaluate: () => ({ verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: "source-sink" }),
};

function payload(value: string, destination: string): EgressPayload {
  return {
    destination,
    sink: "message",
    value,
    byteLength: Buffer.byteLength(value),
    complete: true,
    provenance,
  };
}
