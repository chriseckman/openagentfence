import type { CanonicalAction } from "../action/canonical-action.js";
import type { Finding } from "../contracts/finding.js";
import type { SessionRisk } from "../contracts/risk-state.js";
import type { ReasonCode } from "../policy/reasons.js";

export interface ApprovalRequest {
  readonly id: string;
  readonly sessionId: string;
  readonly action: CanonicalAction;
  readonly findings: readonly Finding[];
  readonly risk: SessionRisk;
  /** ISO 8601 expiry, as exposed to application approval handlers. */
  readonly expiresAt: string;
}

export interface ApprovalDecision {
  readonly approved: boolean;
  readonly scope: "once" | "session";
  readonly reason?: ReasonCode;
  readonly approvedBy?: string;
}

/** Application-registered approval authority (PRD §13.18). */
export interface ApprovalHandler {
  requestApproval(request: ApprovalRequest): Promise<ApprovalDecision>;
}

export interface ApprovalResolutionOptions {
  readonly now?: () => number;
  readonly signal?: AbortSignal;
}

/**
 * Deny-by-default resolution: no handler, a timeout (past `expiresAt`), a
 * thrown error, an explicit rejection, or a malformed return all deny with a
 * stable reason (INV-11). Only a well-formed, approving handler result grants.
 */
export async function resolveApproval(
  handler: ApprovalHandler | undefined,
  request: ApprovalRequest,
  options: ApprovalResolutionOptions = {},
): Promise<ApprovalDecision> {
  if (handler === undefined) {
    return { approved: false, scope: "once", reason: "approval_handler_missing" };
  }
  const now = options.now ?? Date.now;
  const expiresAt = Date.parse(request.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt <= now()) {
    return { approved: false, scope: "once", reason: "approval_timeout" };
  }
  if (options.signal?.aborted === true) {
    return { approved: false, scope: "once", reason: "approval_cancelled" };
  }
  const timeoutMs = expiresAt - now();
  let decision: unknown;
  const outcome = { cancelled: false, timedOut: false };
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const cancellation = new Promise<never>((_, reject) => {
      options.signal?.addEventListener(
        "abort",
        () => {
          outcome.cancelled = true;
          reject(new Error("approval cancelled"));
        },
        { once: true },
      );
    });
    decision = await Promise.race([
      handler.requestApproval(request),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          outcome.timedOut = true;
          reject(new Error("approval timeout"));
        }, timeoutMs);
      }),
      cancellation,
    ]);
  } catch {
    return {
      approved: false,
      scope: "once",
      reason: outcome.cancelled
        ? "approval_cancelled"
        : outcome.timedOut
          ? "approval_timeout"
          : "approval_handler_error",
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  if (now() >= expiresAt) return { approved: false, scope: "once", reason: "approval_timeout" };
  return normalizeDecision(decision);
}

function normalizeDecision(decision: unknown): ApprovalDecision {
  if (!isApprovalDecision(decision)) {
    return { approved: false, scope: "once", reason: "approval_malformed" };
  }
  if (decision.approved) {
    return {
      approved: true,
      scope: decision.scope,
      ...(decision.reason !== undefined ? { reason: decision.reason } : {}),
      ...(decision.approvedBy !== undefined ? { approvedBy: decision.approvedBy } : {}),
    };
  }
  return {
    approved: false,
    scope: decision.scope,
    reason: decision.reason ?? "approval_denied",
  };
}

function isApprovalDecision(value: unknown): value is ApprovalDecision {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record["approved"] === "boolean" &&
    (record["scope"] === "once" || record["scope"] === "session")
  );
}
