import { describe, expect, it } from "vitest";
import {
  MAX_EGRESS_VALUE_BYTES,
  OpenAgentFence,
  REASON_CODES,
  RedactionRegistry,
  actionEgressPayloads,
  createEgressInspector,
  egressMatchForms,
  hash,
} from "../src/index.js";
import type { EgressPayload, VaultAdapter } from "../src/index.js";
import { fakeAdapter, mkAction } from "./helpers.js";

const provenance = { trust: "application" as const, timestamp: "2026-08-19T00:00:00.000Z" };

function datum(value: string, overrides: Partial<EgressPayload> = {}): EgressPayload {
  return {
    destination: "https://blocked.example/collect",
    sink: "routed_request_body",
    value,
    byteLength: Buffer.byteLength(value),
    complete: true,
    provenance,
    ...overrides,
  };
}

describe("destination-aware egress DLP", () => {
  it("matches the complete bounded D-11 set and blocks every unbound form", () => {
    const secret = "  Synthetic-Value~~~  ";
    const registry = new RedactionRegistry();
    registry.registerSecret(secret);
    const inspector = createEgressInspector({
      match: (value, signal) => registry.matchEgress(value, signal),
      isDestinationAllowed: () => false,
    });

    const forms = egressMatchForms(secret);
    expect(forms).toContain(secret.trim().toLowerCase());
    expect(forms).toContain(encodeURIComponent(secret.trim().toUpperCase()));
    expect(forms).toContain(Buffer.from(secret.trim().toLowerCase()).toString("base64"));
    for (const form of forms) {
      const result = inspector.inspect(datum(`prefix:${form}:suffix`));
      expect(result.verdict, form).toBe("block");
      expect(result.reasons, form).toContain(REASON_CODES.sensitive_value_in_egress);
      expect(result.matchCount, form).toBe(1);
    }
  });

  it("allows only the exact approved origin and explicit sink or live field type", () => {
    const secret = "approved-secret";
    const registry = new RedactionRegistry();
    registry.registerSecret(secret);
    const fingerprint = hash(secret);
    const inspector = createEgressInspector({
      match: (value, signal) => registry.matchEgress(value, signal),
      isDestinationAllowed: (candidate, origin, sink, fieldType) =>
        candidate === fingerprint &&
        origin === "https://approved.example" &&
        (sink === "header" || (sink === "typed_value" && fieldType === "password")),
    });

    expect(
      inspector.inspect(
        datum(secret, { destination: "https://approved.example/x", sink: "header" }),
      ).verdict,
    ).toBe("allow");
    expect(
      inspector.inspect(
        datum(secret, {
          destination: "https://approved.example/x",
          sink: "typed_value",
          fieldType: "password",
        }),
      ).verdict,
    ).toBe("allow");
    expect(
      inspector.inspect(
        datum(secret, { destination: "https://approved.example/x", sink: "url_query" }),
      ).verdict,
    ).toBe("block");
    expect(
      inspector.inspect(datum(secret, { destination: "https://other.example/x", sink: "header" }))
        .verdict,
    ).toBe("block");
  });

  it("enforces registered value bindings in the canonical action pipeline", async () => {
    const secret = "pipeline-sensitive-value";
    const vault: VaultAdapter = {
      openSession: () => ({
        store: async (name, _value, kind = "SECRET") => ({
          name,
          kind,
          id: "d".repeat(32),
        }),
        createExecutorLookup: () => ({ lookup: async () => null }),
        invalidateSession: async () => {},
      }),
    };
    const session = new OpenAgentFence({ adapter: fakeAdapter(), vault }).start({
      task: "bounded egress",
      capabilities: { navigation: "allowlist" },
      origins: { allow: ["https://approved.example", "https://blocked.example"] },
      secrets: [
        {
          name: "pipeline",
          kind: "SECRET",
          origins: ["https://approved.example"],
          fieldTypes: ["url_query"],
        },
        {
          name: "account-email",
          kind: "PII",
          origins: ["https://approved.example"],
          fieldTypes: ["url_query"],
        },
      ],
    });
    await session.registerSecret("pipeline", secret);
    const pii = "synthetic.person@example.test";
    await session.registerSecret("account-email", pii, "PII");

    const allowed = await session.authorize(
      mkAction("NAVIGATE", {
        destination: `https://approved.example/collect?value=${encodeURIComponent(secret)}`,
      }),
    );
    expect(allowed.verdict).toBe("ALLOW");
    expect(session.sessionRisk.state).toBe("NORMAL");

    const piiBlocked = await session.authorize(
      mkAction("NAVIGATE", {
        destination: `https://blocked.example/collect?email=${encodeURIComponent(pii)}`,
      }),
    );
    expect(piiBlocked.verdict).toBe("BLOCK");
    expect(piiBlocked.reasons).toContain(REASON_CODES.sensitive_value_in_egress);

    const blocked = await session.authorize(
      mkAction("NAVIGATE", {
        destination: `https://blocked.example/collect?value=${encodeURIComponent(secret)}`,
      }),
    );
    expect(blocked.verdict).toBe("BLOCK");
    expect(blocked.reasons).toContain(REASON_CODES.sensitive_value_in_egress);
    const trace = await session.end();
    expect(JSON.stringify(trace)).not.toContain(secret);
    expect(JSON.stringify(trace)).not.toContain(pii);
    expect(trace.events.some((event) => event.kind === "egress_inspection")).toBe(true);
  });

  it("does not claim forbidden Base64URL or Unicode-folding normalization", () => {
    const registry = new RedactionRegistry();
    registry.registerSecret("~~~");
    registry.registerSecret("token-Å");
    expect(registry.matchEgress(Buffer.from("~~~").toString("base64url")).fingerprints).toEqual([]);
    expect(registry.matchEgress("token-Å".normalize("NFKC")).fingerprints).toEqual([]);
    expect(registry.matchEgress("token-Å".normalize("NFD")).fingerprints).toEqual([]);
  });

  it("fails non-clean on overflow, incomplete extraction, malformed input, and cancellation", () => {
    const inspector = createEgressInspector({
      match: () => ({ fingerprints: [], incomplete: false }),
      isDestinationAllowed: () => false,
    });
    const aborted = new AbortController();
    aborted.abort();
    for (const input of [
      datum("", { byteLength: MAX_EGRESS_VALUE_BYTES + 1 }),
      datum("", { complete: false }),
      datum("", { destination: "" }),
    ]) {
      expect(inspector.inspect(input)).toMatchObject({
        verdict: "block",
        reasons: [REASON_CODES.egress_inspection_incomplete],
      });
    }
    expect(inspector.inspect(datum("safe"), aborted.signal).reasons).toEqual([
      REASON_CODES.egress_inspection_incomplete,
    ]);
  });

  it("extracts URL, typed, form, message, and upload sinks without serializing provenance away", () => {
    const typed = mkAction("FILL", {
      destination: "https://example.com/?q=query#fragment",
      data: "typed",
    });
    const typedPayloads = actionEgressPayloads(typed);
    expect(typedPayloads.map((item) => item.sink)).toEqual([
      "url_query",
      "url_fragment",
      "typed_value",
    ]);
    expect(typedPayloads.every((item) => item.provenance.trust === "application")).toBe(true);

    expect(actionEgressPayloads(mkAction("SUBMIT", { data: { token: "x" } }))[0]?.sink).toBe(
      "form_body",
    );
    expect(actionEgressPayloads(mkAction("MESSAGE", { data: "x" }))[0]?.sink).toBe("message");
    expect(
      actionEgressPayloads(
        mkAction("UPLOAD", {
          data: { filePath: "C:/synthetic.txt", fileName: "synthetic.txt", content: "x" },
        }),
      ).map((item) => item.sink),
    ).toEqual(["upload_path", "upload_name", "text_body"]);
  });

  it("marks structural and byte-limit extraction overflow incomplete", () => {
    const oversized = "x".repeat(MAX_EGRESS_VALUE_BYTES + 1);
    const payload = actionEgressPayloads(mkAction("MESSAGE", { data: oversized }))[0];
    expect(payload).toMatchObject({ complete: false, value: "" });
    expect(payload?.byteLength).toBeGreaterThan(MAX_EGRESS_VALUE_BYTES);
  });
});
