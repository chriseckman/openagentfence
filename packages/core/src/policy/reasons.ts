/**
 * Stable, machine-readable reason codes (INV-17). Every decision that is not
 * `ALLOW` carries at least one code; `openagentfence explain` renders them.
 * Adding a code requires a registry entry here — `PolicyDecision.reasons` is
 * typed to `ReasonCode`, so free-form strings are rejected by the type.
 */
export const REASON_CODES = {
  destination_not_allowed: "destination_not_allowed",
  secret_sink_not_allowed: "secret_sink_not_allowed",
  navigation_instruction_originated_from_untrusted_dom:
    "navigation_instruction_originated_from_untrusted_dom",
  session_contains_high_confidence_prompt_injection:
    "session_contains_high_confidence_prompt_injection",
  scanner_unavailable: "scanner_unavailable",
  unknown_action: "unknown_action",
  capability_denied: "capability_denied",
  private_network_destination: "private_network_destination",
  unsupported_url_scheme: "unsupported_url_scheme",
  redirect_hops_exceeded: "redirect_hops_exceeded",
  session_restricted: "session_restricted",
  budget_exceeded: "budget_exceeded",
  approval_denied: "approval_denied",
  approval_timeout: "approval_timeout",
  approval_cancelled: "approval_cancelled",
  approval_malformed: "approval_malformed",
  approval_handler_error: "approval_handler_error",
  approval_reauthorization_required: "approval_reauthorization_required",
  approval_handler_missing: "approval_handler_missing",
  approval_required: "approval_required",
  execute_script_denied: "execute_script_denied",
  unknown_network_initiator: "unknown_network_initiator",
  network_enforcement_unavailable: "network_enforcement_unavailable",
  network_origin_not_allowed: "network_origin_not_allowed",
  network_metadata_oversized: "network_metadata_oversized",
  network_guard_failure: "network_guard_failure",
  action_intent_mismatch: "action_intent_mismatch",
  action_intent_expired: "action_intent_expired",
  action_policy_mismatch: "action_policy_mismatch",
  action_operation_mismatch: "action_operation_mismatch",
  action_intent_retry_exhausted: "action_intent_retry_exhausted",
  unexpected_redirect: "unexpected_redirect",
  unexpected_tab: "unexpected_tab",
  unexpected_download: "unexpected_download",
  unexpected_origin_change: "unexpected_origin_change",
  post_action_observation_unavailable: "post_action_observation_unavailable",
  post_action_observation_cancelled: "post_action_observation_cancelled",
  post_action_observation_overflow: "post_action_observation_overflow",
} as const;

export type ReasonCode = (typeof REASON_CODES)[keyof typeof REASON_CODES];

export const REASON_CODE_DESCRIPTIONS: Readonly<Record<ReasonCode, string>> = {
  destination_not_allowed: "The action's destination is outside the allowed navigation scope.",
  secret_sink_not_allowed: "A secret would be released to a sink it is not bound to.",
  navigation_instruction_originated_from_untrusted_dom:
    "A navigation instruction originated from untrusted (web) content.",
  session_contains_high_confidence_prompt_injection:
    "The session contains high-confidence prompt injection.",
  scanner_unavailable: "A scanner was unavailable or timed out.",
  unknown_action: "The action could not be recognized and follows the unknown-action default.",
  capability_denied: "The capability envelope does not grant this action.",
  private_network_destination: "The destination is a private/local network address.",
  unsupported_url_scheme: "The destination uses an unsupported or unsafe URL scheme.",
  redirect_hops_exceeded: "The redirect chain exceeded the configured hop limit.",
  session_restricted: "The session risk state forbids this action.",
  budget_exceeded: "A session budget was exhausted.",
  approval_denied: "The approval handler denied the action.",
  approval_timeout: "The approval handler did not respond before the request expired.",
  approval_cancelled: "The approval request was cancelled before a decision was accepted.",
  approval_malformed: "The approval handler returned an invalid decision.",
  approval_handler_error: "The approval handler failed while processing the request.",
  approval_reauthorization_required:
    "Firewall state changed while approval was pending; the action must be authorized again.",
  approval_handler_missing: "No approval handler is registered; the action is denied.",
  approval_required: "A deterministic control requires approval for this action.",
  execute_script_denied: "Arbitrary script execution is denied.",
  unknown_network_initiator: "A network effect has an unknown or malformed initiator.",
  network_enforcement_unavailable: "The adapter cannot enforce this network surface.",
  network_origin_not_allowed:
    "The network effect originates from a disallowed origin or destination.",
  network_metadata_oversized: "The network effect's request metadata exceeded bounds.",
  network_guard_failure: "The Network Mutation Guard could not evaluate the effect.",
  action_intent_mismatch: "The re-resolved page state no longer matches the authorized intent.",
  action_intent_expired: "The authorized action expired before execution.",
  action_policy_mismatch: "The policy hash no longer matches the authorization.",
  action_operation_mismatch: "The exact operation no longer matches the authorized action.",
  action_intent_retry_exhausted: "Reauthorization retries were exhausted.",
  unexpected_redirect: "The executed action produced a redirect outside its authorized effect.",
  unexpected_tab: "The executed action opened an unexpected tab or popup.",
  unexpected_download: "The executed action produced an unexpected download.",
  unexpected_origin_change: "The executed action changed the top-level page origin unexpectedly.",
  post_action_observation_unavailable:
    "The adapter cannot observe required post-action effects; subsequent authority is restricted.",
  post_action_observation_cancelled:
    "Post-action observation was cancelled; subsequent authority is restricted.",
  post_action_observation_overflow:
    "Post-action observation exceeded its bounded event capacity; subsequent authority is restricted.",
};

export function isReasonCode(value: string): value is ReasonCode {
  return (Object.values(REASON_CODES) as readonly string[]).includes(value);
}
