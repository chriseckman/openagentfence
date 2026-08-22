import { describe, expect, it } from "vitest";
import {
  OpenAgentFence,
  REASON_CODES,
  type ActionIntent,
  type PolicyDecision,
  type PolicyEngine,
} from "../src/index.js";
import { fakeAdapter, mkAction } from "./helpers.js";

const allowPolicy: PolicyEngine = {
  policyHash: "taint-floor-test",
  evaluate: (): PolicyDecision => ({
    verdict: "ALLOW",
    reasons: [],
    matchedRules: [],
    policyHash: "taint-floor-test",
  }),
};

function boundIntent(action: ReturnType<typeof mkAction>): ActionIntent {
  const now = Date.now();
  return {
    intentId: "taint-intent",
    actionId: "taint-action",
    action,
    observation: { browserContextId: "context", pageId: "page", revision: 1 },
    target: { origin: "https://good.example" },
    frameOrigin: "https://good.example",
    ...(action.destination !== undefined ? { destination: action.destination } : {}),
    securityAttributes: Object.freeze({}),
    visibility: "visible",
    policyHash: allowPolicy.policyHash,
    operationHash: "operation",
    createdAt: now,
    expiresAt: now + 10_000,
  };
}

describe("session taint floor", () => {
  it("preserves application provenance before release, then caps later actions at web trust", async () => {
    const session = new OpenAgentFence({ adapter: fakeAdapter(), policy: allowPolicy }).start({
      task: "t",
    });
    const before = await session.authorize(mkAction("CLICK"));
    expect(before.action.instructionProvenance.trust).toBe("application");

    await session.observe();
    const after = await session.authorize(mkAction("CLICK"));
    expect(session.sessionTaintFloor?.trust).toBe("web");
    expect(after.action.instructionProvenance.trust).toBe("web");
  });

  it("activates independently of scanner findings and blocks cross-origin navigation deterministically", async () => {
    const session = new OpenAgentFence({ adapter: fakeAdapter(), policy: allowPolicy }).start({
      task: "t",
    });
    await session.observe();

    const crossOrigin = await session.authorize(
      mkAction("NAVIGATE", {
        target: { origin: "https://good.example" },
        destination: "https://evil.example/collect",
      }),
    );
    const sameOrigin = await session.authorize(
      mkAction("NAVIGATE", {
        target: { origin: "https://example.com" },
        destination: "https://example.com/next",
      }),
    );

    expect(crossOrigin.verdict).toBe("BLOCK");
    expect(crossOrigin.reasons).toContain(
      REASON_CODES.navigation_instruction_originated_from_untrusted_dom,
    );
    expect(sameOrigin.verdict).toBe("ALLOW");
  });

  it("activates for released tool output, never recovers across later releases, and traces once", async () => {
    const session = new OpenAgentFence({ adapter: fakeAdapter(), policy: allowPolicy }).start({
      task: "t",
    });
    await session.inspectUntrustedText("tool output", 1_024, {
      trust: "tool",
      origin: "tool://fixture",
      timestamp: "2026-08-19T00:00:00.000Z",
    });
    await session.observe();
    const decision = await session.authorize(mkAction("CLICK"));
    const trace = await session.end();

    expect(decision.action.instructionProvenance).toMatchObject({
      trust: "web",
      origin: "tool://fixture",
    });
    expect(trace.events.filter((event) => event.kind === "taint_activation")).toHaveLength(1);
  });

  it("rejects forged user provenance but accepts an explicit traced TB1 user claim", async () => {
    const session = new OpenAgentFence({ adapter: fakeAdapter(), policy: allowPolicy }).start({
      task: "t",
    });
    await expect(
      session.authorize(mkAction("CLICK", { instructionProvenance: { trust: "user" } })),
    ).rejects.toThrow("user instruction provenance");

    await session.observe();
    const [decision] = await session.authorizeActions([mkAction("CLICK")], {
      instructedBy: "user",
    });
    const trace = await session.end();
    expect(decision?.action.instructionProvenance.trust).toBe("user");
    expect(trace.events.some((event) => event.kind === "trusted_instruction_claim")).toBe(true);
  });

  it("invalidates a state-bound authorization when a later context release activates the floor", async () => {
    const session = new OpenAgentFence({ adapter: fakeAdapter(), policy: allowPolicy }).start({
      task: "t",
    });
    const action = mkAction("CLICK", { target: { origin: "https://good.example" } });
    const bound = await session.authorizeBound(action, boundIntent(action));
    expect(bound.authorized).toBeDefined();
    if (bound.authorized === undefined) throw new Error("expected an authorized action");

    await session.inspectUntrustedText("released after authorization");
    await expect(session.executeAuthorized(bound.authorized)).rejects.toThrow(
      "authorization requires full reauthorization",
    );
  });
});
