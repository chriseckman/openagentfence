import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  isValidatedPolicyDocument,
  loadPolicyDocument,
  parsePolicyDocumentSource,
  PolicyDocumentError,
} from "../src/index.js";

const fixture = (name: string): string =>
  fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

async function expectInvalid(work: () => unknown): Promise<void> {
  try {
    await work();
  } catch (error: unknown) {
    expect(error).toMatchObject({ name: "PolicyDocumentError", code: "POLICY_DOCUMENT_INVALID" });
    return;
  }
  throw new Error("expected policy document loading to fail");
}

describe("bounded policy document loader", () => {
  it("loads the PRD YAML example as a branded immutable document", async () => {
    const policy = await loadPolicyDocument(fixture("policy-valid.yml"));
    expect(policy.version).toBe(1);
    expect(policy.actions?.purchase).toBe("approval");
    expect(isValidatedPolicyDocument(policy)).toBe(true);
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.navigation)).toBe(true);
  });

  it("loads JSON by extension and rejects a wrong enum with a path-qualified error", async () => {
    await expectInvalid(() =>
      parsePolicyDocumentSource('{"version":1,"navigation":{"mode":"everywhere"}}', "policy.json"),
    );
  });

  it("rejects unknown provider configuration without exposing its value", async () => {
    await expectInvalid(() => loadPolicyDocument(fixture("policy-invalid-unknown.yml")));
  });

  it("rejects aliases, explicit tags, duplicate keys, directives, and deep YAML", async () => {
    await expectInvalid(() => loadPolicyDocument(fixture("policy-alias.yml")));
    await expectInvalid(() => loadPolicyDocument(fixture("policy-tag.yml")));
    await expectInvalid(() => parsePolicyDocumentSource("version: 1\nversion: 1", "duplicate.yml"));
    await expectInvalid(() =>
      parsePolicyDocumentSource("%YAML 1.2\n---\nversion: 1", "directive.yml"),
    );
    await expectInvalid(() =>
      parsePolicyDocumentSource(
        `version: 1\nscanners:\n${"  nested:\n".repeat(20)}    enabled: true`,
        "deep.yml",
      ),
    );
  });

  it("rejects environment substitution, pollution keys, and oversized input", async () => {
    await expectInvalid(() =>
      parsePolicyDocumentSource(
        "version: 1\nsuppressions:\n  - rule: ${UNTRUSTED}\n    scope: test\n    justification: test",
        "environment.yml",
      ),
    );
    await expectInvalid(() =>
      parsePolicyDocumentSource('{"version":1,"__proto__":{"polluted":true}}', "pollution.json"),
    );
    const oversized = `version: 1\n# ${"x".repeat(1024 * 1024)}`;
    expect(() => parsePolicyDocumentSource(oversized, "large.yml")).toThrow(
      "exceeds 1048576 bytes",
    );
  });

  it("rejects malformed JSON and unreadable policy paths without leaking parser output", async () => {
    await expectInvalid(() => parsePolicyDocumentSource('{"version":', "malformed.json"));
    await expectInvalid(() => loadPolicyDocument(fixture("missing.yml")));
  });

  it("rejects invalid values across every declared policy section", async () => {
    await expectInvalid(() =>
      loadPolicyDocument({
        version: 2,
        defaults: {
          unknown_action: "allow",
          scanner_failure: { low_risk: "allow", high_risk: "warn" },
        },
        navigation: { mode: "internet", block_private_networks: "true" },
        actions: { upload: "block", invented: "allow" },
        secrets: { resolution: "browser" },
        injection: { high_confidence: "allow", critical: "allow" },
        budgets: {
          max_actions: -1,
          max_duration_ms: Number.NaN,
          max_navigations: "one",
          on_exceeded: "warn",
        },
        scanners: { injection: { enabled: "yes", extra: true } },
        suppressions: [{ rule: "", scope: "", justification: "", expires: 3 }],
        risk: { restricted_at: -1, quarantine_at: "high" },
      } as unknown as { readonly version: 1 }),
    );
  });

  it("rejects invalid, expired, and deterministic-control suppressions", async () => {
    for (const suppression of [
      { rule: "hidden", scope: "*", justification: "synthetic", expires: "not-a-date" },
      { rule: "hidden", scope: "*", justification: "synthetic", expires: "2000-01-01" },
      { rule: "secret_sink_not_allowed", scope: "*", justification: "synthetic" },
    ]) {
      await expectInvalid(() => loadPolicyDocument({ version: 1, suppressions: [suppression] }));
    }
  });

  it("accepts all declared optional sections and rejects non-plain programmatic input", async () => {
    const policy = await loadPolicyDocument({
      version: 1,
      defaults: { scanner_failure: { low_risk: "block" } },
      navigation: { mode: "allowlist", block_private_networks: false },
      actions: { download: "allow" },
      secrets: { resolution: "executor_only" },
      injection: { high_confidence: "block", critical: "block" },
      budgets: { max_actions: 1, max_duration_ms: 2, max_navigations: 3, on_exceeded: "block" },
      scanners: { deterministic: { enabled: true } },
      suppressions: [
        { rule: "example", scope: "local", justification: "synthetic", expires: "2030-01-01" },
      ],
      risk: { restricted_at: 1, quarantine_at: 2 },
    });
    expect(policy.scanners?.deterministic?.enabled).toBe(true);
    const exotic = Object.create({ inherited: true }) as { version: 1 };
    exotic.version = 1;
    await expectInvalid(() => loadPolicyDocument(exotic));
  });

  it("does not mutate or trust a caller-owned document", async () => {
    const input = { version: 1, navigation: { mode: "same-site" } } as const;
    const policy = await loadPolicyDocument(input);
    expect(policy).not.toBe(input);
    expect(Object.isFrozen(policy)).toBe(true);
  });

  it("rejects unbounded or malformed internal network ranges and redirect limits", async () => {
    await expectInvalid(() =>
      loadPolicyDocument({
        version: 1,
        navigation: { max_redirect_hops: 6, internal_network_ranges: ["not-a-cidr"] },
      }),
    );
  });

  it("publishes a versioned schema that describes the runtime boundary", async () => {
    const schema = JSON.parse(
      await readFile(
        new URL("../schemas/openagentfence-policy.schema.json", import.meta.url),
        "utf8",
      ),
    ) as Record<string, unknown>;
    expect(schema["$id"]).toBe("https://openagentfence.dev/schemas/openagentfence-policy/v1.json");
    expect((schema["properties"] as Record<string, unknown>)["version"]).toMatchObject({
      const: 1,
    });
  });
});

describe("policy loader failures", () => {
  it("uses a bounded error shape", () => {
    const error = new PolicyDocumentError(
      "POLICY_DOCUMENT_INVALID",
      Array.from({ length: 30 }, (_, index) => `policy.${index}: invalid`),
    );
    expect(error.errors).toHaveLength(20);
  });
});
