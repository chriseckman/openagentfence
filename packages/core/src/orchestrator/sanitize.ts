/**
 * Sanitization application (ARCHITECTURE §6). A scanner may return span-level
 * redactions (`SanitizationSpan`) and/or a whole-text `sanitized` replacement.
 * Span-level sanitizations are applied sequentially in scanner priority order,
 * each later transformation operating on the already-sanitized text; where
 * spans overlap, the most restrictive wins (removal beats replacement).
 * Provenance is preserved by the caller (sanitization never adds trust).
 */

export interface SanitizationSpan {
  /** Inclusive start offset in the original text. */
  readonly start: number;
  /** Exclusive end offset in the original text. */
  readonly end: number;
  /** Replacement text; the empty string is a removal (most restrictive). */
  readonly replacement: string;
}

/**
 * Apply span-level sanitizations with overlap resolution where a removal wins
 * over a replacement. Spans are supplied in priority order; the result is
 * deterministic for a given input and span list.
 */
export function applySanitizationSpans(base: string, spans: readonly SanitizationSpan[]): string {
  if (spans.length === 0) {
    return base;
  }
  const clamped = spans
    .filter((s) => s.end >= s.start)
    .sort((a, b) => a.start - b.start || b.end - a.end);

  const resolved: SanitizationSpan[] = [];
  for (const span of clamped) {
    let overlapped = false;
    for (let i = 0; i < resolved.length; i += 1) {
      const existing = resolved[i];
      if (existing === undefined) {
        continue;
      }
      const overlap = span.start < existing.end && span.end > existing.start;
      if (overlap && span.replacement === "" && existing.replacement !== "") {
        // Removal beats replacement on overlap.
        resolved[i] = span;
        overlapped = true;
        break;
      }
      if (overlap && existing.replacement === "") {
        // Existing removal beats a replacement.
        overlapped = true;
        break;
      }
    }
    if (!overlapped) {
      resolved.push(span);
    }
  }

  const ordered = resolved.sort((a, b) => a.start - b.start);
  let result = "";
  let cursor = 0;
  for (const span of ordered) {
    const start = Math.min(Math.max(span.start, cursor), base.length);
    const end = Math.min(Math.max(span.end, start), base.length);
    result += base.slice(cursor, start);
    result += span.replacement;
    cursor = end;
  }
  result += base.slice(cursor);
  return result;
}

/** Whole-text sanitization: later output operates on prior sanitized text. */
export function applySanitizations(base: string, sanitized: readonly string[]): string {
  let current = base;
  for (const next of sanitized) {
    current = next;
  }
  return current;
}
