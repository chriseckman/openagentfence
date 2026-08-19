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
  RedactionRegistry,
  TraceWriter,
} from "../src/index.js";
import type { NetworkMutation } from "../src/index.js";

function mutation(overrides: Partial<NetworkMutation> = {}): NetworkMutation {
  return {
    surface: "fetch",
    initiator: "page_script",
    origin: "https://page.example",
    destination: "https://evil.example/exfil",
    enforcement: "observed_only",
    ...overrides,
  };
}

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
    expect(schema["required"]).toEqual(["surface", "initiator", "destination", "enforcement"]);
    const props = schema["properties"] as Record<string, unknown>;
    expect((props["surface"] as Record<string, unknown>)["enum"]).toEqual([...NETWORK_SURFACES]);
    expect((props["initiator"] as Record<string, unknown>)["enum"]).toEqual([
      ...NETWORK_INITIATORS,
    ]);
  });
});
