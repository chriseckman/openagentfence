import {
  createPolicyRuntimeState,
  type ValidatedPolicyRuntimeState,
} from "../policy/runtime-state.js";
import type { BudgetConfig } from "../contracts/task-contract.js";

export type BudgetKind =
  | "actions"
  | "navigations"
  | "redirectHops"
  | "guardCalls"
  | "guardTokens"
  | "downloads"
  | "downloadBytes"
  | "uploadBytes"
  | "tabs";

export interface BudgetUse {
  readonly kind: BudgetKind;
  readonly amount?: number;
}

export interface BudgetSnapshot {
  readonly actions: number;
  readonly navigations: number;
  readonly redirectHops: number;
  readonly guardCalls: number;
  readonly guardTokens: number;
  readonly downloads: number;
  readonly downloadBytes: number;
  readonly uploadBytes: number;
  readonly tabs: number;
  readonly elapsedMs: number;
}

export interface SessionClock {
  now(): number;
}

export const systemSessionClock: SessionClock = Object.freeze({ now: () => Date.now() });

/** Synchronous session-owned accounting; check-and-consume is atomic in one JS turn. */
export class SessionBudgetLedger {
  private readonly used: Record<BudgetKind, number> = {
    actions: 0,
    navigations: 0,
    redirectHops: 0,
    guardCalls: 0,
    guardTokens: 0,
    downloads: 0,
    downloadBytes: 0,
    uploadBytes: 0,
    tabs: 0,
  };

  constructor(
    private readonly budget: BudgetConfig | undefined,
    private readonly startedAt: number,
    private readonly clock: SessionClock = systemSessionClock,
  ) {}

  tryConsume(kind: BudgetKind, amount = 1): boolean {
    return this.tryConsumeAll([{ kind, amount }]);
  }

  /**
   * Reserve several limits as one synchronous transaction. This is deliberately
   * all-or-nothing: an action that needs both an action and navigation slot
   * cannot consume only one before being refused (INV-09, INV-16).
   */
  tryConsumeAll(uses: readonly BudgetUse[]): boolean {
    if (this.isExpired()) return false;
    const requested: Record<BudgetKind, number> = { ...this.used };
    for (const use of uses) {
      const amount = use.amount ?? 1;
      if (!Number.isFinite(amount) || amount < 0) return false;
      requested[use.kind] += amount;
    }
    for (const kind of Object.keys(requested) as BudgetKind[]) {
      const limit = this.limitFor(kind);
      if (limit !== undefined && requested[kind] > limit) return false;
    }
    for (const kind of Object.keys(this.used) as BudgetKind[]) {
      this.used[kind] = requested[kind];
    }
    return true;
  }

  isExpired(): boolean {
    const limit = this.budget?.maxDurationMs;
    return limit !== undefined && this.elapsedMs() >= limit;
  }

  elapsedMs(): number {
    return Math.max(0, this.clock.now() - this.startedAt);
  }

  snapshot(): BudgetSnapshot {
    return Object.freeze({ ...this.used, elapsedMs: this.elapsedMs() });
  }

  runtimeState(): ValidatedPolicyRuntimeState {
    return createPolicyRuntimeState({
      budget: {
        actionsUsed: this.used.actions,
        navigationsUsed: this.used.navigations,
        elapsedMs: this.elapsedMs(),
      },
      scannerEvidence: [],
    });
  }

  private limitFor(kind: BudgetKind): number | undefined {
    switch (kind) {
      case "actions":
        return this.budget?.maxActions;
      case "navigations":
        return this.budget?.maxNavigations;
      case "redirectHops":
        return this.budget?.maxRedirectHops;
      case "guardCalls":
        return this.budget?.maxGuardCalls;
      case "guardTokens":
        return this.budget?.maxGuardTokens;
      case "downloads":
        return this.budget?.maxDownloads;
      case "downloadBytes":
        return this.budget?.maxDownloadBytes;
      case "uploadBytes":
        return this.budget?.maxUploadBytes;
      case "tabs":
        return this.budget?.maxTabs;
    }
  }
}
