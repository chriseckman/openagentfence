import { describe, expect, it } from "vitest";
import { OpenAgentFence } from "../src/index.js";
import { fakeAdapter } from "./helpers.js";

describe("OpenAgentFence facade", () => {
  it("validates the contract at start and rejects invalid input", () => {
    const firewall = new OpenAgentFence({ adapter: fakeAdapter() });
    expect(() => firewall.start({})).toThrow(TypeError);
    expect(() => firewall.start({ task: "x", bogus: true })).toThrow(TypeError);
  });

  it("compiles a secure-default envelope from a valid contract", () => {
    const firewall = new OpenAgentFence({ adapter: fakeAdapter() });
    const session = firewall.start({ task: "read a page" });
    expect(session.riskState).toBe("NORMAL");
    expect(session.envelope.evaluate({ type: "UPLOAD" }).allowed).toBe(false);
    expect(session.envelope.evaluate({ type: "READ" }).allowed).toBe(true);
  });

  it("denies approval by default", async () => {
    const firewall = new OpenAgentFence({ adapter: fakeAdapter() });
    const session = firewall.start({ task: "t" });
    const decision = await session.requestApproval(
      { type: "PURCHASE", instructionProvenance: { trust: "application" } },
      [],
    );
    expect(decision.approved).toBe(false);
    expect(decision.reason).toBe("approval_handler_missing");
  });

  it("records escape-hatch use in the trace", async () => {
    const events: string[] = [];
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      trace: { write: (e) => events.push(e.kind) },
    });
    const session = firewall.start({ task: "t" });
    session.unsafe.rawPage("for testing");
    await session.end();
    expect(events).toContain("escape_hatch");
    expect(events).toContain("session_start");
    expect(events).toContain("session_end");
  });

  it("binds adapter listeners to the firewall session and detaches them on end", async () => {
    let subscribedSessionId: string | undefined;
    let detached = false;
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter({
        subscribe: (sessionId) => {
          subscribedSessionId = sessionId;
          return () => {
            detached = true;
          };
        },
      }),
    });
    const session = firewall.start({ task: "t" });
    expect(subscribedSessionId).toBe(session.id);
    await session.end();
    expect(detached).toBe(true);
  });

  it("returns bounded adapter text as untrusted content", async () => {
    const firewall = new OpenAgentFence({ adapter: fakeAdapter() });
    const session = firewall.start({ task: "t" });
    const content = await session.inspectUntrustedText("tool output");
    expect(content.provenance.trust).toBe("web");
    expect(content.instructionEligible).toBe(false);
    await expect(session.inspectUntrustedText("x".repeat(20), 10)).rejects.toBeInstanceOf(
      RangeError,
    );
    await session.end();
  });
});
