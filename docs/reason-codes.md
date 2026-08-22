# Reason codes

Every decision other than `ALLOW` carries stable, machine-readable reason
codes. `openagentfence explain` displays only these codes and redacted hashes;
it never renders page text, secret values, provider payloads, or raw action
data.

| Code | Meaning |
| --- | --- |
| `destination_not_allowed` | The action destination is outside its navigation scope. |
| `secret_sink_not_allowed` | A secret would resolve to an unbound sink. |
| `sensitive_value_in_egress` | A registered sensitive value would leave through an unapproved destination. |
| `egress_inspection_incomplete` | Required egress inspection was cancelled, malformed, or exceeded bounds. |
| `untrusted_cross_origin_egress` | Tainted or sensitive data would leave through an untrusted cross-origin sink. |
| `navigation_instruction_originated_from_untrusted_dom` | A navigation instruction came from untrusted web content. |
| `session_contains_high_confidence_prompt_injection` | The session contains high-confidence prompt injection. |
| `scanner_unavailable` | A scanner was unavailable or timed out. |
| `unknown_action` | An unrecognized action follows the secure unknown-action default. |
| `capability_denied` | The capability envelope does not grant the action. |
| `private_network_destination` | The destination is private or local. |
| `unsupported_url_scheme` | The destination URL scheme is unsafe or unsupported. |
| `redirect_hops_exceeded` | The redirect chain exceeded its hop limit. |
| `session_restricted` | Current session risk forbids the action. |
| `budget_exceeded` | A session budget is exhausted. |
| `approval_denied` | The approval handler denied the action. |
| `approval_timeout` | The approval response did not arrive before expiry. |
| `approval_cancelled` | The approval request was cancelled. |
| `approval_malformed` | The approval handler returned an invalid result. |
| `approval_handler_error` | The approval handler failed. |
| `approval_reauthorization_required` | Firewall state changed while approval was pending. |
| `approval_handler_missing` | No approval handler is registered, so the action is denied. |
| `approval_required` | A deterministic control requires approval. |
| `execute_script_denied` | Arbitrary script execution is denied. |
| `unknown_network_initiator` | A network effect has an unknown or malformed initiator. |
| `network_enforcement_unavailable` | The adapter cannot enforce that network surface. |
| `network_origin_not_allowed` | The effect has a disallowed origin or destination. |
| `network_metadata_oversized` | Request metadata exceeded its bounds. |
| `network_guard_failure` | The Network Mutation Guard could not evaluate the effect. |
| `action_intent_mismatch` | Live page state no longer matches authorization. |
| `action_intent_expired` | Authorization expired before execution. |
| `action_policy_mismatch` | The policy hash changed after authorization. |
| `action_operation_mismatch` | The exact operation changed after authorization. |
| `action_intent_retry_exhausted` | Reauthorization retries were exhausted. |
| `unexpected_redirect` | Execution caused an unauthorized redirect effect. |
| `unexpected_tab` | Execution opened an unexpected tab or popup. |
| `unexpected_download` | Execution caused an unexpected download. |
| `unexpected_origin_change` | Execution changed the top-level origin unexpectedly. |
| `post_action_observation_unavailable` | Required post-action observation is unavailable. |
| `post_action_observation_cancelled` | Post-action observation was cancelled. |
| `post_action_observation_overflow` | Post-action event capacity was exceeded. |

The canonical registry is `packages/core/src/policy/reasons.ts`. New codes must
add a source description and this documentation entry.
