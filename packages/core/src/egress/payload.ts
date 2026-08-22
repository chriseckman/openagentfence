import type { DataProvenance } from "../contracts/provenance.js";

export const EGRESS_SINKS = [
  "url_query",
  "url_fragment",
  "form_body",
  "typed_value",
  "message",
  "header",
  "upload_name",
  "upload_path",
  "text_body",
  "routed_request_body",
] as const;

export type EgressSink = (typeof EGRESS_SINKS)[number];

/** Ephemeral raw datum for a required deterministic egress check. Never serialize it. */
export interface EgressPayload {
  readonly destination: string;
  readonly sink: EgressSink;
  readonly value: string;
  readonly byteLength: number;
  readonly complete: boolean;
  readonly provenance: DataProvenance;
  /** Live executor-derived field type for a typed sink, when available. */
  readonly fieldType?: string;
}
