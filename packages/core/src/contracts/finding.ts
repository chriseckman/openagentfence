import type { DataProvenance } from "./provenance.js";
import type { RedactedEvidence } from "../trace/redact.js";

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

export type Severity = (typeof SEVERITIES)[number];

export interface BoundingBox {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export type FindingSourceType =
  "dom" | "url" | "probe" | "model" | "tool" | "memory" | "file" | "header";

export interface FindingSource {
  readonly type: FindingSourceType;
  readonly selector?: string;
  readonly xpath?: string;
  readonly origin?: string;
  readonly frameOrigin?: string;
  readonly boundingBox?: BoundingBox;
}

export interface Finding {
  readonly id: string;
  readonly category: string;
  readonly title: string;
  readonly description: string;
  readonly source: FindingSource;
  readonly provenance: DataProvenance;
  readonly evidence: RedactedEvidence;
  readonly recommendedAction: "allow" | "warn" | "sanitize" | "approve" | "block";
  readonly severity?: Severity;
  readonly confidence?: number;
}
