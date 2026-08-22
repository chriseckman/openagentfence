import { isIntentExpired, type ActionIntent } from "../action/intent.js";
import { originOf } from "../action/url.js";
import { REASON_CODES, type ReasonCode } from "../policy/reasons.js";
import type { NetworkMutation } from "./mutation.js";

export type NetworkIntentCorrelationStatus = "none" | "matched" | "mismatched" | "expired";

/** Redacted evidence about a claimed mutation/intent relationship. Never authority. */
export interface NetworkIntentCorrelation {
  readonly status: NetworkIntentCorrelationStatus;
  readonly intentId?: string;
  readonly reasons: readonly ReasonCode[];
}

/**
 * Check an adapter-supplied correlation claim against the currently executing
 * intent. A match is useful trace evidence only: the mutation still passes the
 * complete Network Mutation Guard over its actual facts (INV-19/21).
 */
export function correlateNetworkMutation(
  mutation: NetworkMutation,
  activeIntent: ActionIntent | undefined,
  now: number = Date.now(),
): NetworkIntentCorrelation {
  const claimed = mutation.actionIntentId;
  if (claimed === undefined) return { status: "none", reasons: [] };
  if (activeIntent === undefined || activeIntent.intentId !== claimed) {
    return {
      status: "mismatched",
      intentId: claimed,
      reasons: [REASON_CODES.action_intent_mismatch],
    };
  }
  if (isIntentExpired(activeIntent, now)) {
    return {
      status: "expired",
      intentId: claimed,
      reasons: [REASON_CODES.action_intent_expired],
    };
  }
  if (
    mutation.provenance.pageId !== undefined &&
    mutation.provenance.pageId !== activeIntent.observation.pageId
  ) {
    return {
      status: "mismatched",
      intentId: claimed,
      reasons: [REASON_CODES.action_intent_mismatch],
    };
  }
  const expected = activeIntent.destination ?? activeIntent.formAction;
  if (expected !== undefined && originOf(expected) !== originOf(mutation.destination)) {
    return {
      status: "mismatched",
      intentId: claimed,
      reasons: [REASON_CODES.action_intent_mismatch],
    };
  }
  return { status: "matched", intentId: claimed, reasons: [] };
}
