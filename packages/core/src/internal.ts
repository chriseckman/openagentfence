import type { Authorized } from "./action/authorized.js";
import type { SecuritySession } from "./session/session.js";

/** @internal Test and core-composition helper; never part of the root API. */
export { createVaultExecutorAccess } from "./secrets/vault-access.js";

/** @internal Adapter-only capability symbol; it is deliberately absent from the root API. */
export const STAGEHAND_EXECUTION: unique symbol = Symbol("openagentfence.stagehand.execution");

/** @internal Exact executor shape used only by the Stagehand adapter package. */
export interface ExactActionExecutor {
  execute(): Promise<unknown>;
}

type StagehandExecution = (
  authorized: Authorized,
  executor: ExactActionExecutor,
) => Promise<unknown>;

/**
 * @internal
 * Execute a session-issued authorization through the supported Stagehand
 * adapter bridge. It is intentionally not exported by `@openagentfence/core`.
 */
export function executeStagehandAuthorized(
  session: SecuritySession,
  authorized: Authorized,
  executor: ExactActionExecutor,
): Promise<unknown> {
  const candidate = (session as unknown as Record<symbol, unknown>)[STAGEHAND_EXECUTION];
  if (typeof candidate !== "function") {
    throw new TypeError("Stagehand exact-execution bridge is unavailable for this session");
  }
  return (candidate as StagehandExecution)(authorized, executor);
}
