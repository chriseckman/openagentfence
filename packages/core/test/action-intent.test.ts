import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import fc from "fast-check";
import {
  validateActionIntent,
  computeIntentFingerprint,
  compareIntentState,
  isIntentExpired,
  isAuthorizedAction,
  denyAllResolver,
  validateTraceDocument,
  RedactionRegistry,
  TraceWriter,
  OpenAgentFence,
} from "../src/index.js";
import { mintAuthorizedAction } from "../src/action/authorized.js";
import type { ActionIntent, CanonicalAction, IntentStateSnapshot } from "../src/index.js";
import { fakeAdapter } from "./helpers.js";

function intent(overrides: Partial<ActionIntent> = {}): ActionIntent {
  return {
    intentId: "i1",
    actionId: "a1",
    action: {
      type: "NAVIGATE",
      destination: "https://shop.example/checkout",
      instructionProvenance: { trust: "application" },
    },
    observation: { browserContextId: "ctx", pageId: "page", revision: 1 },
    target: { selector: "#checkout" },
    securityAttributes: { href: "/checkout" },
    visibility: "visible",
    policyHash: "policy-hash",
    operationHash: "op-hash",
    createdAt: 1000,
    expiresAt: 2000,
    ...overrides,
  };
}

function snapshot(overrides: Partial<IntentStateSnapshot> = {}): IntentStateSnapshot {
  const base = intent();
  return {
    observation: base.observation,
    target: base.target,
    securityAttributes: base.securityAttributes,
    visibility: base.visibility,
    policyHash: base.policyHash,
    operationHash: base.operationHash,
    ...overrides,
  };
}

describe("ActionIntent validation", () => {
  it("accepts a valid intent and rejects malformed ones", () => {
    expect(validateActionIntent(intent())).not.toBeNull();
    expect(validateActionIntent({})).toBeNull();
    expect(validateActionIntent(intent({ intentId: "" }))).toBeNull();
    expect(
      validateActionIntent(intent({ observation: { browserContextId: "c" } as never })),
    ).toBeNull();
    expect(validateActionIntent(intent({ expiresAt: "soon" as never }))).toBeNull();
    expect(validateActionIntent(intent({ extra: true } as never))).toBeNull();
  });

  it("never throws on arbitrary JSON-like input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateActionIntent(value)).not.toThrow();
      }),
    );
  });
});

describe("state fingerprinting", () => {
  it("is deterministic and property-order independent", () => {
    const a = intent();
    const b = intent({
      securityAttributes: { href: "/checkout", disabled: "false" },
    });
    const c = intent({
      securityAttributes: { disabled: "false", href: "/checkout" },
    });
    expect(computeIntentFingerprint(a)).toBe(computeIntentFingerprint(a));
    expect(computeIntentFingerprint(b)).toBe(computeIntentFingerprint(c));
    expect(computeIntentFingerprint(a)).not.toBe(computeIntentFingerprint(b));
  });
});

describe("intent state comparison", () => {
  it("reports no mismatch for identical state", () => {
    expect(compareIntentState(intent(), snapshot())).toEqual([]);
  });

  it("produces a stable mismatch code for each changed bound field", () => {
    expect(compareIntentState(intent(), snapshot({ target: { selector: "#other" } }))).toContain(
      "target",
    );
    expect(
      compareIntentState(intent(), snapshot({ destination: "https://evil.example" })),
    ).toContain("destination");
    expect(compareIntentState(intent(), snapshot({ visibility: "hidden" }))).toContain(
      "visibility",
    );
    expect(compareIntentState(intent(), snapshot({ policyHash: "other" }))).toContain("policy");
    expect(compareIntentState(intent(), snapshot({ operationHash: "other" }))).toContain(
      "operation",
    );
    expect(
      compareIntentState(
        intent(),
        snapshot({ observation: { browserContextId: "ctx", pageId: "page", revision: 2 } }),
      ),
    ).toContain("observation");
  });

  it("does not mutate the bound intent", () => {
    const original = intent();
    const frozen = Object.freeze(JSON.parse(JSON.stringify(original)));
    void compareIntentState(
      frozen as ActionIntent,
      snapshot({ destination: "https://other.example" }),
    );
    expect((frozen as ActionIntent).destination).toBe(original.destination);
  });
});

describe("expiry", () => {
  it("treats the expiry boundary as exclusive", () => {
    const i = intent({ createdAt: 0, expiresAt: 1000 });
    expect(isIntentExpired(i, 999)).toBe(false);
    expect(isIntentExpired(i, 1000)).toBe(true);
    expect(isIntentExpired(i, 1001)).toBe(true);
  });
});

describe("AuthorizedAction brand", () => {
  it("mints a frozen branded action only through mintAuthorizedAction", () => {
    const authorized = mintAuthorizedAction({
      action: intent().action,
      intent: intent(),
      operationHash: "op-hash",
      policyHash: "policy-hash",
      decisionId: "d1",
      traceId: "t1",
    });
    expect(isAuthorizedAction(authorized)).toBe(true);
    expect(Object.isFrozen(authorized)).toBe(true);
  });

  it("rejects a forged object and hash mismatches", () => {
    expect(isAuthorizedAction({ action: {}, intent: {}, operationHash: "x" })).toBe(false);
    expect(isAuthorizedAction(null)).toBe(false);
    expect(() =>
      mintAuthorizedAction({
        action: intent().action,
        intent: intent(),
        operationHash: "wrong",
        policyHash: "policy-hash",
        decisionId: "d1",
        traceId: "t1",
      }),
    ).toThrow();
    expect(() =>
      mintAuthorizedAction({
        action: intent().action,
        intent: intent(),
        operationHash: "op-hash",
        policyHash: "wrong",
        decisionId: "d1",
        traceId: "t1",
      }),
    ).toThrow();
  });

  it("type-level: a raw CanonicalAction cannot reach the guarded executor", () => {
    const adapter = fakeAdapter();
    const raw: CanonicalAction = {
      type: "NAVIGATE",
      instructionProvenance: { trust: "application" },
    };
    expect(isAuthorizedAction(raw)).toBe(false);
    // @ts-expect-error — executeAuthorized accepts only AuthorizedAction
    void adapter.executeAuthorized(raw, denyAllResolver);
  });
});

describe("issued authorization lifecycle", () => {
  it("invalidates an unconsumed authorization after firewall-owned budget state changes", async () => {
    const executeAuthorized = vi.fn(async () => undefined);
    const adapter = fakeAdapter({ executeAuthorized });
    const session = new OpenAgentFence({ adapter }).start({ task: "state binding" });
    const action: CanonicalAction = {
      type: "CLICK",
      target: { element: "#continue", origin: "https://example.com" },
      instructionProvenance: { trust: "application" },
      raw: { adapter: "test", operation: "click" },
    };
    const now = Date.now();
    const bound = await session.authorizeBound(action, {
      intentId: "intent-budget-state",
      actionId: "action-budget-state",
      action,
      observation: { browserContextId: "context", pageId: "page", revision: 1 },
      target: { selector: "#continue", origin: "https://example.com" },
      securityAttributes: {},
      visibility: "visible",
      policyHash: session.policyEngine.policyHash,
      operationHash: "test-operation",
      createdAt: now,
      expiresAt: now + 10_000,
    });
    if (bound.authorized === undefined) throw new Error("expected authorization");

    expect(session.reserveBudget([{ kind: "actions" }])).toBe(true);
    await expect(session.executeAuthorized(bound.authorized)).rejects.toThrow(
      "approval_reauthorization_required",
    );
    expect(executeAuthorized).not.toHaveBeenCalled();

    const trace = await session.end();
    expect(trace.events.some((event) => event.kind === "action_revalidation")).toBe(true);
  });
});

describe("authorization trace events", () => {
  it("records redacted authorized_action and action_revalidation events", async () => {
    const redactor = new RedactionRegistry();
    redactor.registerSecret("s3cr3t-token");
    const writer = new TraceWriter(redactor);
    writer.start({
      sessionId: "s",
      policyHash: "h",
      capabilities: fakeAdapter().capabilities,
      versions: { schema: "1.0.0" },
    });
    writer.append("authorized_action", {
      intentId: "i1",
      operationHash: "op",
      policyHash: "policy",
    });
    writer.append("action_revalidation", {
      reason: "action_intent_mismatch",
      stateHash: "abc",
      leaked: "s3cr3t-token",
    });
    const doc = writer.document();
    expect(JSON.stringify(doc)).not.toContain("s3cr3t-token");
    expect(validateTraceDocument(doc).ok).toBe(true);
  });
});

describe("schema agreement (action intent/authorized schemas)", () => {
  function loadSchema(name: string): Record<string, unknown> {
    const schemasDir = join(dirname(fileURLToPath(import.meta.url)), "..", "schemas");
    return JSON.parse(readFileSync(join(schemasDir, name), "utf8")) as Record<string, unknown>;
  }

  it("publishes closed action-intent and authorized-action schemas", () => {
    const intentSchema = loadSchema("action-intent.schema.json");
    expect(intentSchema["$id"]).toBe(
      "https://openagentfence.dev/schemas/action-intent.schema.json",
    );
    expect(intentSchema["additionalProperties"]).toBe(false);
    expect(intentSchema["required"]).toContain("operationHash");
    expect(intentSchema["required"]).toContain("expiresAt");

    const authSchema = loadSchema("authorized-action.schema.json");
    expect(authSchema["$id"]).toBe(
      "https://openagentfence.dev/schemas/authorized-action.schema.json",
    );
    expect(authSchema["additionalProperties"]).toBe(false);
    expect(authSchema["required"]).toContain("intent");
  });
});
