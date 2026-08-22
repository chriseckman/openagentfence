import { describe, expect, it, vi } from "vitest";
import { resolveApproval } from "../src/index.js";
import type { ApprovalDecision, ApprovalHandler, ApprovalRequest } from "../src/index.js";
import { mkAction } from "./helpers.js";

function request(expiresIn = 1000): ApprovalRequest {
  return {
    id: "1",
    sessionId: "s",
    action: mkAction("PURCHASE"),
    findings: [],
    risk: { state: "NORMAL", score: 0 },
    expiresAt: new Date(Date.now() + expiresIn).toISOString(),
  };
}

describe("approval resolution (deny-by-default)", () => {
  it("denies when no handler is registered", async () => {
    const d = await resolveApproval(undefined, request());
    expect(d.approved).toBe(false);
    expect(d.reason).toBe("approval_handler_missing");
  });

  it("denies on timeout", async () => {
    vi.useFakeTimers();
    const handler = { requestApproval: () => new Promise<never>(() => {}) };
    const p = resolveApproval(handler, request(100));
    await vi.advanceTimersByTimeAsync(200);
    const d = await p;
    expect(d.approved).toBe(false);
    expect(d.reason).toBe("approval_timeout");
    vi.useRealTimers();
  });

  it("denies on a thrown error", async () => {
    const handler = {
      requestApproval: async () => {
        throw new Error("boom");
      },
    };
    const d = await resolveApproval(handler, request());
    expect(d.approved).toBe(false);
    expect(d.reason).toBe("approval_handler_error");
  });

  it("denies malformed responses and already-expired requests", async () => {
    const malformed: ApprovalHandler = {
      requestApproval: async () => ({ invalid: true }) as unknown as ApprovalDecision,
    };
    expect((await resolveApproval(malformed, request())).reason).toBe("approval_malformed");
    expect((await resolveApproval(malformed, request(-1))).reason).toBe("approval_timeout");
  });

  it("cancels a pending handler and ignores its late approval", async () => {
    let approveLate: ((decision: ApprovalDecision) => void) | undefined;
    const handler: ApprovalHandler = {
      requestApproval: () =>
        new Promise<ApprovalDecision>((resolve) => {
          approveLate = resolve;
        }),
    };
    const controller = new AbortController();
    const pending = resolveApproval(handler, request(), { signal: controller.signal });
    controller.abort();
    const decision = await pending;
    approveLate?.({ approved: true, scope: "session" });
    expect(decision).toMatchObject({ approved: false, reason: "approval_cancelled" });
  });

  it("approves when the handler approves", async () => {
    const handler = { requestApproval: async () => ({ approved: true, scope: "once" as const }) };
    const d = await resolveApproval(handler, request());
    expect(d.approved).toBe(true);
    expect(d.scope).toBe("once");
  });
});
