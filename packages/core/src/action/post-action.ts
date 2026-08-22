import type { AdapterEvent } from "../adapter/browser-adapter.js";
import type { BrowserAdapterCapabilities } from "../adapter/capabilities.js";
import type { CanonicalAction } from "./canonical-action.js";
import type { ActionIntent } from "./intent.js";
import { originOf, sameOrigin } from "./url.js";

/** Short quiescence interval after exact execution; it is detection, never prevention. */
export const POST_ACTION_SETTLE_MS = 25;
export const POST_ACTION_MAX_EVENTS = 32;

export type PostActionStatus = "complete" | "unavailable" | "cancelled" | "overflow";

export type PostActionReason =
  | "unexpected_redirect"
  | "unexpected_tab"
  | "unexpected_download"
  | "unexpected_origin_change"
  | "post_action_observation_unavailable"
  | "post_action_observation_cancelled"
  | "post_action_observation_overflow";

export interface PostActionObservation {
  readonly intentId: string;
  readonly action: CanonicalAction;
  readonly intent: ActionIntent;
  readonly startedOrigin?: string;
  readonly events: readonly AdapterEvent[];
  readonly status: PostActionStatus;
}

/** Derive expected effects solely from the exact action accepted before execution. */
export function comparePostAction(observation: PostActionObservation): readonly PostActionReason[] {
  if (observation.status !== "complete") return [statusReason(observation.status)];
  const expectedOrigin = expectedDestinationOrigin(observation.action);
  const reasons: PostActionReason[] = [];
  for (const event of observation.events) {
    if (event.kind === "popup") {
      reasons.push("unexpected_tab");
      continue;
    }
    if (event.kind === "download") {
      if (!isExpectedDownload(observation.action, event.origin))
        reasons.push("unexpected_download");
      continue;
    }
    if (event.mainFrame !== true || event.origin === undefined) continue;
    if (expectedOrigin !== undefined) {
      if (!sameOrigin(event.origin, expectedOrigin)) reasons.push("unexpected_redirect");
    } else if (
      observation.startedOrigin !== undefined &&
      !sameOrigin(event.origin, observation.startedOrigin)
    ) {
      reasons.push("unexpected_origin_change");
    }
  }
  return [...new Set(reasons)];
}

/** Missing observation is never reported as a clean post-action result. */
export function postActionCapabilitiesAvailable(capabilities: BrowserAdapterCapabilities): boolean {
  return capabilities.navigationEvents && capabilities.popupEvents && capabilities.downloadEvents;
}

function expectedDestinationOrigin(action: CanonicalAction): string | undefined {
  if (action.type !== "NAVIGATE" && action.type !== "SUBMIT") return undefined;
  return action.destination === undefined ? undefined : (originOf(action.destination) ?? undefined);
}

function isExpectedDownload(action: CanonicalAction, observedOrigin: string | undefined): boolean {
  if (action.type !== "DOWNLOAD") return false;
  if (action.destination === undefined || observedOrigin === undefined) return true;
  const expected = originOf(action.destination);
  return expected !== null && sameOrigin(expected, observedOrigin);
}

function statusReason(status: Exclude<PostActionStatus, "complete">): PostActionReason {
  switch (status) {
    case "unavailable":
      return "post_action_observation_unavailable";
    case "cancelled":
      return "post_action_observation_cancelled";
    case "overflow":
      return "post_action_observation_overflow";
  }
}
