export const TRACE_SCHEMA_VERSION = "1.0.0";

/**
 * Version of `@openagentfence/core`, recorded in session-start traces. Kept in
 * sync with `packages/core/package.json` until the build pipeline derives it.
 */
export const CORE_VERSION = "0.0.0";

export const TRACE_EVENT_KINDS = [
  "session_start",
  "observation",
  "finding",
  "scan_result",
  "proposed_action",
  "canonical_action",
  "policy_decision",
  "approval_request",
  "approval_decision",
  "execution",
  "post_action",
  "risk_change",
  "budget_event",
  "escape_hatch",
  "network_mutation",
  "adapter_event",
  "authorized_action",
  "action_revalidation",
  "session_end",
] as const;

export type TraceEventKind = (typeof TRACE_EVENT_KINDS)[number];

export interface TraceEvent {
  readonly kind: TraceEventKind;
  readonly timestamp: string;
  readonly data: Readonly<Record<string, unknown>>;
}

export interface TraceDocument {
  readonly schemaVersion: string;
  readonly events: readonly TraceEvent[];
}

/**
 * A reproducible, redacted evidence reference attached to a non-ALLOW decision
 * (INV-17). It points at a finding by id and carries a hash of its redacted
 * evidence so `explain` and replay can resolve the reference without ever
 * holding raw evidence or secrets.
 */
export interface EvidenceReference {
  readonly findingId: string;
  readonly category: string;
  readonly evidenceHash: string;
  readonly sourceType: string;
}
