import { describe, expect, it, vi } from "vitest";
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

  it("creates guard-backed scanners per session through the budget-owning callback", async () => {
    const classify = vi.fn(async () => ({
      promptInjection: false,
      confidence: 0.9,
      categories: [],
      recommendedVerdict: "allow" as const,
    }));
    let factories = 0;
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      guardModel: { name: "fake", model: "fake", makesExternalCalls: false, classify },
      guardScannerFactories: [
        (runGuard) => {
          factories += 1;
          return {
            id: `guard-backed-${factories}`,
            phases: ["MODEL_OUTPUT"],
            kind: "semantic",
            tier: "tier2",
            async scan(ctx) {
              const outcome = await runGuard(
                {
                  role: "text_injection",
                  excerpts: [ctx.redactor.redact("bounded excerpt")],
                  taskSummary: ctx.redactor.redact("task"),
                  localeHints: [],
                  budget: { maxTokens: 2 },
                },
                {
                  signal: ctx.signal,
                  deadline: ctx.deadline,
                  maxInputBytes: 100,
                  maxOutputBytes: 1000,
                  maxTokens: 2,
                },
              );
              return {
                scanner: `guard-backed-${factories}`,
                kind: "semantic",
                verdict: outcome.ok ? "allow" : "warn",
                severity: outcome.ok ? "info" : "low",
                findings: [],
              };
            },
          };
        },
      ],
    });
    const first = firewall.start({ task: "first" });
    await first.inspectUntrustedText("first output");
    await first.end();
    const second = firewall.start({ task: "second" });
    await second.inspectUntrustedText("second output");
    await second.end();
    expect(factories).toBe(2);
    expect(classify).toHaveBeenCalledTimes(2);
  });

  it("blocks high-impact actions after a required guard failure but permits harmless reads", async () => {
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      guardModel: {
        name: "malformed",
        model: "fixture",
        makesExternalCalls: false,
        classify: async () => ({ authority: "allow" }),
      },
      guardScannerFactories: [
        (runGuard) => ({
          id: "required-guard",
          phases: ["MODEL_OUTPUT"],
          kind: "semantic",
          tier: "tier2",
          required: true,
          async scan(ctx) {
            const outcome = await runGuard(
              {
                role: "text_injection",
                excerpts: [ctx.redactor.redact("bounded")],
                taskSummary: ctx.redactor.redact("task"),
                localeHints: [],
              },
              {
                signal: ctx.signal,
                deadline: ctx.deadline,
                maxInputBytes: 100,
                maxOutputBytes: 100,
                maxTokens: 1,
              },
            );
            return {
              scanner: "required-guard",
              kind: "semantic",
              verdict: outcome.ok ? "allow" : "warn",
              severity: outcome.ok ? "info" : "low",
              findings: [],
              ...(!outcome.ok ? { metadata: { failureKind: outcome.kind } } : {}),
            };
          },
        }),
      ],
    });
    const session = firewall.start({ task: "read safely" });
    await session.inspectUntrustedText("harmless output");
    expect(
      (await session.authorize({ type: "READ", instructionProvenance: { trust: "application" } }))
        .verdict,
    ).toBe("ALLOW");
    const sideEffect = await session.authorize({
      type: "CLICK",
      instructionProvenance: { trust: "application" },
    });
    expect(sideEffect.verdict).toBe("BLOCK");
    expect(sideEffect.reasons).toContain("scanner_unavailable");
    await session.end();
  });
});
