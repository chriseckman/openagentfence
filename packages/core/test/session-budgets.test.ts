import { describe, expect, it } from "vitest";
import { SessionBudgetLedger, type SessionClock } from "../src/index.js";

function clock(start = 0): { readonly clock: SessionClock; advance(ms: number): void } {
  let now = start;
  return { clock: { now: () => now }, advance: (ms) => (now += ms) };
}

describe("session budget ledger", () => {
  it("permits the exact action/navigation limit and refuses the next reservation", () => {
    const fake = clock();
    const ledger = new SessionBudgetLedger({ maxActions: 2, maxNavigations: 1 }, 0, fake.clock);
    expect(ledger.tryConsume("actions")).toBe(true);
    expect(ledger.tryConsume("actions")).toBe(true);
    expect(ledger.tryConsume("actions")).toBe(false);
    expect(ledger.tryConsume("navigations")).toBe(true);
    expect(ledger.tryConsume("navigations")).toBe(false);
  });

  it("uses an injected monotonic clock for the duration boundary", () => {
    const fake = clock();
    const ledger = new SessionBudgetLedger({ maxDurationMs: 10 }, 0, fake.clock);
    fake.advance(9);
    expect(ledger.tryConsume("actions")).toBe(true);
    fake.advance(1);
    expect(ledger.isExpired()).toBe(true);
    expect(ledger.tryConsume("actions")).toBe(false);
  });

  it("atomically reserves all required limits without partial consumption", () => {
    const ledger = new SessionBudgetLedger({ maxActions: 1, maxNavigations: 0 }, 0);
    expect(ledger.tryConsumeAll([{ kind: "actions" }, { kind: "navigations" }])).toBe(false);
    expect(ledger.snapshot()).toMatchObject({ actions: 0, navigations: 0 });
  });

  it("does not refund a consumed guard slot when its guarded work is cancelled", () => {
    const ledger = new SessionBudgetLedger({ maxGuardCalls: 1 }, 0);
    // A provider may be cancelled after dispatch. Retaining the consumed slot
    // is monotonic and prevents cancellation from widening session authority.
    expect(ledger.tryConsume("guardCalls")).toBe(true);
    expect(ledger.tryConsume("guardCalls")).toBe(false);
    expect(ledger.snapshot().guardCalls).toBe(1);
  });

  it("accounts for every P0 boundary budget with exact limits", () => {
    const ledger = new SessionBudgetLedger(
      {
        maxRedirectHops: 1,
        maxGuardCalls: 1,
        maxGuardTokens: 2,
        maxDownloads: 1,
        maxDownloadBytes: 3,
        maxUploadBytes: 4,
        maxTabs: 1,
      },
      0,
    );
    expect(ledger.tryConsume("redirectHops")).toBe(true);
    expect(ledger.tryConsume("redirectHops")).toBe(false);
    expect(ledger.tryConsume("guardCalls")).toBe(true);
    expect(ledger.tryConsume("guardTokens", 2)).toBe(true);
    expect(ledger.tryConsume("downloads")).toBe(true);
    expect(ledger.tryConsume("downloadBytes", 3)).toBe(true);
    expect(ledger.tryConsume("uploadBytes", 4)).toBe(true);
    expect(ledger.tryConsume("tabs")).toBe(true);
    expect(ledger.tryConsume("guardCalls")).toBe(false);
    expect(ledger.tryConsume("guardTokens")).toBe(false);
    expect(ledger.tryConsume("downloads")).toBe(false);
    expect(ledger.tryConsume("downloadBytes")).toBe(false);
    expect(ledger.tryConsume("uploadBytes")).toBe(false);
    expect(ledger.tryConsume("tabs")).toBe(false);
  });
});
