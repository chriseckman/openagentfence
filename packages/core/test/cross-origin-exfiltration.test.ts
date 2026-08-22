import { describe, expect, it, vi } from "vitest";
import {
  EXFILTRATION_ACTION_TYPES,
  OpenAgentFence,
  REASON_CODES,
  defineScanner,
  evaluateCrossOriginExfiltration,
  type PolicyDecision,
  type PolicyEngine,
} from "../src/index.js";
import { fakeAdapter, mkAction } from "./helpers.js";

const allowPolicy: PolicyEngine = {
  policyHash: "exfil-test",
  evaluate: (): PolicyDecision => ({
    verdict: "ALLOW",
    reasons: [],
    matchedRules: [],
    policyHash: "exfil-test",
  }),
};

describe("fixed cross-origin exfiltration rule", () => {
  it("blocks every required action for tainted data at an unbound cross-origin sink", () => {
    for (const type of EXFILTRATION_ACTION_TYPES) {
      const action = mkAction(type, {
        target: { origin: "https://source.example" },
        destination: "https://unbound.example/collect",
        data: "tainted",
      });
      const result = evaluateCrossOriginExfiltration(action, {
        currentOrigin: "https://source.example",
        sessionTainted: true,
        valueMatched: false,
        handlePresent: false,
        exactSinkBound: false,
        destinationInTaskScope: false,
      });
      expect(result.blocked, type).toBe(true);
      expect(result.reasons, type).toContain(REASON_CODES.untrusted_cross_origin_egress);
      expect(result.reasons, type).toContain(REASON_CODES.secret_sink_not_allowed);
      expect(result.reasons, type).toContain(REASON_CODES.destination_not_allowed);
    }
  });

  it("permits same-origin and exact-bound NORMAL sinks only past this rule", () => {
    const sameOrigin = mkAction("MESSAGE", {
      target: { origin: "https://source.example" },
      destination: "https://source.example/message",
      data: "tainted",
    });
    const crossOrigin = mkAction("MESSAGE", {
      target: { origin: "https://source.example" },
      destination: "https://bound.example/message",
      data: "registered",
    });
    const base = {
      currentOrigin: "https://source.example",
      sessionTainted: true,
      valueMatched: false,
      handlePresent: false,
      exactSinkBound: false,
      destinationInTaskScope: true,
    };
    expect(evaluateCrossOriginExfiltration(sameOrigin, base).blocked).toBe(false);
    expect(
      evaluateCrossOriginExfiltration(crossOrigin, {
        ...base,
        valueMatched: true,
        exactSinkBound: true,
      }).blocked,
    ).toBe(false);
  });

  it("fails closed when a sensitive side-effect destination cannot be proven", () => {
    const result = evaluateCrossOriginExfiltration(mkAction("PASTE", { data: "x" }), {
      sessionTainted: false,
      valueMatched: false,
      handlePresent: true,
      exactSinkBound: false,
      destinationInTaskScope: false,
    });
    expect(result).toMatchObject({
      blocked: true,
      reasons: expect.arrayContaining([
        REASON_CODES.untrusted_cross_origin_egress,
        REASON_CODES.secret_sink_not_allowed,
      ]),
    });
  });

  it("blocks a declared handle on every non-executor exfiltration sink", async () => {
    const session = new OpenAgentFence({ adapter: fakeAdapter(), policy: allowPolicy }).start({
      task: "do not move handles through messages",
      capabilities: { messaging: true, externalCommunication: true, credentials: true },
      origins: { allow: ["https://source.example", "https://bound.example"] },
      secrets: [
        {
          name: "declared",
          kind: "SECRET",
          origins: ["https://bound.example"],
          fieldTypes: ["message"],
        },
      ],
    });
    const decision = await session.authorize(
      mkAction("MESSAGE", {
        target: { origin: "https://source.example" },
        destination: "https://bound.example/message",
        data: `<SECRET:declared:${"b".repeat(32)}>`,
      }),
    );
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasons).toContain(REASON_CODES.secret_sink_not_allowed);
    await session.end();
  });

  it("survives absent/fake-safe/throwing scanners and escalates repeated attempts monotonically", async () => {
    const fakeSafe = vi.fn(async () => ({
      scanner: "fake-safe",
      kind: "semantic" as const,
      verdict: "allow" as const,
      severity: "info" as const,
      findings: [],
    }));
    const scanner = defineScanner({
      id: "fake-safe",
      phases: ["PRE_ACTION"],
      kind: "semantic",
      scan: fakeSafe,
    });
    const session = new OpenAgentFence({
      adapter: fakeAdapter(),
      policy: allowPolicy,
      scanners: [scanner],
    }).start({
      task: "tainted message containment",
      capabilities: { messaging: true, externalCommunication: true },
      origins: { allow: ["https://example.com", "https://unbound.example"] },
    });
    await session.observe();
    const action = mkAction("MESSAGE", {
      target: { origin: "https://example.com" },
      destination: "https://unbound.example/collect",
      data: "model-produced text",
    });
    const states: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      const decision = await session.authorize(action);
      expect(decision.verdict).toBe("BLOCK");
      expect(decision.reasons).toContain(REASON_CODES.untrusted_cross_origin_egress);
      expect(decision.reasons).toContain(REASON_CODES.secret_sink_not_allowed);
      states.push(session.sessionRisk.state);
    }
    expect(fakeSafe).not.toHaveBeenCalled();
    expect(states).toEqual(["RESTRICTED", "READ_ONLY", "QUARANTINED"]);
    const trace = await session.end();
    expect(trace.events.filter((event) => event.kind === "risk_change")).toHaveLength(3);
    expect(JSON.stringify(trace)).not.toContain("model-produced text");
  });
});
