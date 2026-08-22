import type { CanonicalAction } from "./canonical-action.js";
import type { ActionIntent } from "./intent.js";
import { validateActionIntent } from "./intent.js";

/**
 * A successful, state-bound authorization (ADR-0010, INV-19). The brand is a
 * runtime `unique symbol` applied only by `mintAuthorizedAction`, which is the
 * single constructor reachable from the deterministic authorization path. A raw
 * `CanonicalAction` cannot satisfy this type, and `isAuthorizedAction` rejects
 * any forged object.
 */
export interface AuthorizedAction {
  readonly action: CanonicalAction;
  readonly intent: ActionIntent;
  readonly operationHash: string;
  readonly policyHash: string;
  readonly decisionId: string;
  readonly traceId: string;
  readonly createdAt: number;
}

const AUTHORIZED: unique symbol = Symbol("openagentfence.action.authorized");

export type Authorized = AuthorizedAction & { readonly [AUTHORIZED]: true };

/** Runtime guard for the authorization brand. */
export function isAuthorizedAction(value: unknown): value is Authorized {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.isFrozen(value) &&
    Object.getOwnPropertySymbols(value).includes(AUTHORIZED)
  );
}

export interface MintAuthorizedInput {
  readonly action: CanonicalAction;
  readonly intent: ActionIntent;
  readonly operationHash: string;
  readonly policyHash: string;
  readonly decisionId: string;
  readonly traceId: string;
  readonly createdAt?: number;
}

/**
 * Mint the branded authorization. The intent is validated, and the operation
 * and policy hashes must match the intent. Callers pass a sanitized action
 * (no raw secrets). Only this function applies the brand symbol.
 */
export function mintAuthorizedAction(input: MintAuthorizedInput): Authorized {
  const intent = validateActionIntent(input.intent);
  if (intent === null) {
    throw new TypeError("invalid ActionIntent");
  }
  if (input.operationHash !== intent.operationHash) {
    throw new TypeError("operationHash does not match the intent");
  }
  if (input.policyHash !== intent.policyHash) {
    throw new TypeError("policyHash does not match the intent");
  }
  const value: AuthorizedAction = {
    action: input.action,
    intent,
    operationHash: input.operationHash,
    policyHash: input.policyHash,
    decisionId: input.decisionId,
    traceId: input.traceId,
    createdAt: input.createdAt ?? Date.now(),
  };
  const branded = Object.defineProperty(value, AUTHORIZED, {
    value: true as const,
    enumerable: false,
  }) as Authorized;
  return Object.freeze(branded);
}
