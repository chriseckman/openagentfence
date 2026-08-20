import {
  TRACE_SCHEMA_VERSION,
  type TraceDocument,
  type TraceEvent,
  type TraceEventKind,
} from "./events.js";
import type { Redactor } from "./redact.js";

export interface TraceSink {
  write(event: TraceEvent): void;
}

/**
 * Append-only, redacted trace writer (ARCHITECTURE §14, INV-05). Every event is
 * defensively redacted before it is emitted: registered secret values never
 * reach a sink. The writer never buffers raw secrets.
 */
export class TraceWriter {
  private readonly events: TraceEvent[] = [];
  private readonly sinks: TraceSink[] = [];

  constructor(private readonly redactor: Redactor) {}

  attach(sink: TraceSink): void {
    this.sinks.push(sink);
  }

  start(data: Readonly<Record<string, unknown>>): void {
    this.events.length = 0;
    this.append("session_start", data);
  }

  append(kind: TraceEventKind, data: Readonly<Record<string, unknown>>): void {
    const event: TraceEvent = {
      kind,
      timestamp: new Date().toISOString(),
      data: redactDeep(data, this.redactor) as Readonly<Record<string, unknown>>,
    };
    this.events.push(event);
    for (const sink of this.sinks) {
      sink.write(event);
    }
  }

  document(): TraceDocument {
    return { schemaVersion: TRACE_SCHEMA_VERSION, events: [...this.events] };
  }
}

export function redactDeep(
  value: unknown,
  redactor: Redactor,
  depth = 0,
  seen = new WeakSet(),
): unknown {
  if (depth > 16) return "[REDACTED:DEPTH]";
  if (typeof value === "string") {
    return redactor.redact(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactDeep(item, redactor));
  }
  if (typeof value === "object" && value !== null) {
    if (seen.has(value)) return "[REDACTED:CYCLE]";
    seen.add(value);
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = redactDeep(item, redactor, depth + 1, seen);
    }
    return out;
  }
  return value;
}
