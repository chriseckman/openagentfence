import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  NETWORK_SURFACES,
  NETWORK_INITIATORS,
  DEFAULT_NETWORK_CAPABILITIES,
  validateNetworkMutation,
  validateNetworkCapabilities,
  evaluateNetworkMutation,
  correlateNetworkMutation,
  compileTaskContract,
  validateTaskContract,
  RedactionRegistry,
  TraceWriter,
} from "../src/index.js";
import type { NetworkMutation } from "../src/index.js";
import type { ActionIntent } from "../src/index.js";

function mutation(overrides: Partial<NetworkMutation> = {}): NetworkMutation {
  return {
    surface: "fetch",
    initiator: "page_script",
    origin: "https://page.example",
    destination: "https://evil.example/exfil",
    enforcement: "observed_only",
    provenance: { trust: "web", timestamp: "2026-01-01T00:00:00.000Z" },
    ...overrides,
  };
}

function networkEnvelope(overrides: Record<string, unknown> = {}) {
  const result = validateTaskContract({
    task: "network test",
    capabilities: { privateNetwork: true, navigation: "allowlist", externalCommunication: true },
    origins: { allow: ["https://page.example", "https://api.example"] },
    ...overrides,
  });
  if (!result.ok) throw new Error(result.errors.join("; "));
  return compileTaskContract(result.value);
}

const cleanEgress = {
  verdict: "allow" as const,
  reasons: [],
  inspectedBytes: 0,
  matchCount: 0,
};

describe("network mutation validation", () => {
  it("represents every named surface and initiator", () => {
    for (const surface of NETWORK_SURFACES) {
      for (const initiator of NETWORK_INITIATORS) {
        const m = mutation({ surface, initiator });
        expect(validateNetworkMutation(m), `${surface}/${initiator}`).not.toBeNull();
      }
    }
  });

  it("rejects unknown surface, initiator, and enforcement", () => {
    expect(validateNetworkMutation(mutation({ surface: "bogus" as never }))).toBeNull();
    expect(validateNetworkMutation(mutation({ initiator: "nearby_action" as never }))).toBeNull();
    expect(validateNetworkMutation(mutation({ enforcement: "maybe" as never }))).toBeNull();
  });

  it("requires a bounded destination", () => {
    expect(validateNetworkMutation(mutation({ destination: "" }))).toBeNull();
    expect(validateNetworkMutation(mutation({ destination: "x".repeat(5000) }))).toBeNull();
  });

  it("bounds request metadata and rejects malformed shapes", () => {
    const valid = mutation({
      metadata: {
        method: "POST",
        headers: { "content-type": "application/json" },
        bodyHash: "a".repeat(64),
        bodySize: 1024,
      },
    });
    expect(validateNetworkMutation(valid)).not.toBeNull();

    expect(
      validateNetworkMutation(mutation({ metadata: { headers: { h: "x".repeat(3000) } } })),
    ).toBeNull();
    expect(
      validateNetworkMutation(mutation({ metadata: { headers: { h: "v" }, bodyHash: "not-hex" } })),
    ).toBeNull();
    expect(
      validateNetworkMutation(mutation({ metadata: { headers: {}, bodySize: -1 } })),
    ).toBeNull();
    expect(
      validateNetworkMutation(mutation({ metadata: { method: "GET", headers: {} } })),
    ).not.toBeNull();
  });

  it("rejects oversized intent ids", () => {
    expect(validateNetworkMutation(mutation({ actionIntentId: "x".repeat(200) }))).toBeNull();
    expect(validateNetworkMutation(mutation({ actionIntentId: "intent-1" }))).not.toBeNull();
  });

  it("accepts bounded redirect-hop facts and rejects malformed values", () => {
    expect(
      validateNetworkMutation(mutation({ surface: "redirect", redirectHops: 5 })),
    ).not.toBeNull();
    expect(validateNetworkMutation(mutation({ redirectHops: -1 }))).toBeNull();
    expect(validateNetworkMutation(mutation({ redirectHops: 101 }))).toBeNull();
    expect(validateNetworkMutation(mutation({ redirectHops: 1.5 }))).toBeNull();
  });

  it("never throws on arbitrary JSON-like input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateNetworkMutation(value)).not.toThrow();
        expect(() => validateNetworkCapabilities(value)).not.toThrow();
      }),
    );
  });
});

describe("network capability matrix", () => {
  it("accepts the conservative default matrix", () => {
    expect(validateNetworkCapabilities(DEFAULT_NETWORK_CAPABILITIES)).not.toBeNull();
  });

  it("rejects a matrix missing a surface or adding an unknown surface", () => {
    const missing = { ...DEFAULT_NETWORK_CAPABILITIES };
    delete (missing as Record<string, unknown>)["fetch"];
    expect(validateNetworkCapabilities(missing)).toBeNull();

    expect(
      validateNetworkCapabilities({ ...DEFAULT_NETWORK_CAPABILITIES, dns: "enforced" }),
    ).toBeNull();
  });

  it("rejects non-enforcement values (observation cannot become enforcement)", () => {
    expect(
      validateNetworkCapabilities({ ...DEFAULT_NETWORK_CAPABILITIES, fetch: "maybe" }),
    ).toBeNull();
  });
});

describe("independent Network Mutation Guard", () => {
  it("allows a benign same-origin enforced request and blocks private or DLP traffic", () => {
    const envelope = networkEnvelope();
    const benign = mutation({
      destination: "https://page.example/api",
      enforcement: "enforced",
    });
    expect(
      evaluateNetworkMutation({
        mutation: benign,
        envelope,
        riskState: "NORMAL",
        egressInspection: cleanEgress,
      }).verdict,
    ).toBe("continue");

    const privateResult = evaluateNetworkMutation({
      mutation: mutation({ destination: "http://127.0.0.1/private", enforcement: "enforced" }),
      envelope: networkEnvelope({
        capabilities: {
          privateNetwork: false,
          navigation: "allowlist",
          externalCommunication: true,
        },
      }),
      riskState: "NORMAL",
      egressInspection: cleanEgress,
    });
    expect(privateResult.verdict).toBe("block");
    expect(privateResult.reasons).toContain("private_network_destination");

    const dlpResult = evaluateNetworkMutation({
      mutation: { ...benign, destination: "https://api.example/collect" },
      envelope,
      riskState: "NORMAL",
      egressInspection: {
        verdict: "block",
        reasons: ["sensitive_value_in_egress"],
        inspectedBytes: 12,
        matchCount: 1,
      },
    });
    expect(dlpResult.verdict).toBe("block");
    expect(dlpResult.reasons).toContain("sensitive_value_in_egress");
  });

  it("never reports observed-only or unavailable surfaces as clean", () => {
    for (const surface of NETWORK_SURFACES) {
      for (const enforcement of ["observed_only", "unavailable"] as const) {
        const result = evaluateNetworkMutation({
          mutation: mutation({ surface, enforcement }),
          envelope: networkEnvelope(),
          riskState: "NORMAL",
        });
        expect(result.verdict, `${surface}/${enforcement}`).toBe("observe_only_gap");
        expect(result.reasons).toContain("network_enforcement_unavailable");
      }
    }
  });

  it("fails enforced evaluation closed when provenance or DLP evidence is unavailable", () => {
    const envelope = networkEnvelope();
    expect(
      evaluateNetworkMutation({
        mutation: mutation({ enforcement: "enforced" }),
        envelope,
        riskState: "NORMAL",
      }).reasons,
    ).toContain("network_guard_failure");
    expect(
      evaluateNetworkMutation({
        mutation: mutation({ enforcement: "enforced", provenance: { trust: "application" } }),
        envelope,
        riskState: "NORMAL",
        egressInspection: cleanEgress,
      }).verdict,
    ).toBe("block");
  });

  it("treats matched, absent, mismatched, and expired intents as evidence only", () => {
    const activeIntent: ActionIntent = {
      intentId: "intent-current",
      actionId: "action-current",
      action: { type: "READ", instructionProvenance: { trust: "application" } },
      observation: { browserContextId: "ctx", pageId: "page-1", revision: 1 },
      target: { origin: "https://page.example" },
      securityAttributes: {},
      visibility: "visible",
      policyHash: "policy",
      operationHash: "operation",
      createdAt: 100,
      expiresAt: 200,
    };
    const base = mutation({
      destination: "https://page.example/api",
      enforcement: "enforced",
      provenance: { trust: "web", pageId: "page-1" },
    });
    expect(correlateNetworkMutation(base, activeIntent, 150).status).toBe("none");
    expect(
      correlateNetworkMutation({ ...base, actionIntentId: "intent-current" }, activeIntent, 150)
        .status,
    ).toBe("matched");
    expect(
      correlateNetworkMutation({ ...base, actionIntentId: "intent-other" }, activeIntent, 150)
        .status,
    ).toBe("mismatched");
    const expired = correlateNetworkMutation(
      { ...base, actionIntentId: "intent-current" },
      activeIntent,
      200,
    );
    expect(expired.status).toBe("expired");
    const result = evaluateNetworkMutation({
      mutation: { ...base, actionIntentId: "intent-other" },
      envelope: networkEnvelope(),
      riskState: "NORMAL",
      egressInspection: cleanEgress,
      correlation: correlateNetworkMutation(
        { ...base, actionIntentId: "intent-other" },
        activeIntent,
        150,
      ),
    });
    expect(result.verdict).toBe("continue");
    expect(result.reasons).toContain("action_intent_mismatch");
  });
});

describe("network mutation trace redaction", () => {
  it("never writes raw secrets present in mutation metadata", () => {
    const redactor = new RedactionRegistry();
    redactor.registerSecret("s3cr3t-exfil");
    const writer = new TraceWriter(redactor);
    writer.start({
      sessionId: "s",
      policyHash: "h",
      capabilities: DEFAULT_NETWORK_CAPABILITIES,
      versions: { schema: "1.0.0" },
    });
    writer.append("network_mutation", {
      surface: "fetch",
      initiator: "page_script",
      destination: "https://evil.example",
      enforcement: "observed_only",
      metadata: { headers: { authorization: "Bearer s3cr3t-exfil" } },
    });
    const serialized = JSON.stringify(writer.document());
    expect(serialized).not.toContain("s3cr3t-exfil");
    expect(serialized).toContain("network_mutation");
  });
});

describe("schema agreement (network mutation validator vs published schema)", () => {
  function loadSchema(): Record<string, unknown> {
    const schemasDir = join(dirname(fileURLToPath(import.meta.url)), "..", "schemas");
    return JSON.parse(
      readFileSync(join(schemasDir, "network-mutation.schema.json"), "utf8"),
    ) as Record<string, unknown>;
  }

  it("is closed, has a stable id, and matches the surface/initiator enums", () => {
    const schema = loadSchema();
    expect(schema["$id"]).toBe("https://openagentfence.dev/schemas/network-mutation.schema.json");
    expect(schema["additionalProperties"]).toBe(false);
    expect(schema["required"]).toEqual([
      "surface",
      "initiator",
      "destination",
      "enforcement",
      "provenance",
    ]);
    const props = schema["properties"] as Record<string, unknown>;
    expect((props["surface"] as Record<string, unknown>)["enum"]).toEqual([...NETWORK_SURFACES]);
    expect((props["initiator"] as Record<string, unknown>)["enum"]).toEqual([
      ...NETWORK_INITIATORS,
    ]);
  });
});
