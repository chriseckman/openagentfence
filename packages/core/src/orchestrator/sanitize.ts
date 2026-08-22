/**
 * Sanitization application (ARCHITECTURE §6). A scanner may return span-level
 * redactions (`SanitizationSpan`) and/or a whole-text `sanitized` replacement.
 * Span-level sanitizations are applied sequentially in scanner priority order,
 * each later transformation operating on the already-sanitized text; where
 * spans overlap, the most restrictive wins (removal beats replacement).
 * Provenance is attached to each span at the scanner boundary; sanitization
 * never adds or upgrades trust.
 */

import type { DataProvenance, ProvenancedDatum } from "../contracts/provenance.js";

export interface SanitizationSpan {
  /** Inclusive start offset in the original text. */
  readonly start: number;
  /** Exclusive end offset in the original text. */
  readonly end: number;
  /** Replacement text; the empty string is a removal (most restrictive). */
  readonly replacement: string;
  /** Source retained through the transformation; required at TB9. */
  readonly provenance: DataProvenance;
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
export function applySanitizations(
  base: string,
  sanitized: readonly ProvenancedDatum<string>[],
): string {
  let current = base;
  for (const next of sanitized) {
    current = next.value;
  }
  return current;
}

/**
 * Compose whole-text and span sanitizers without allowing a whole-text result
 * from one scanner to restore a value removed by another scanner. Whole-text
 * results are independent canonical views, so their offsets cannot safely be
 * reused; exact source slices are therefore re-applied to the final view.
 */
export function applySanitizationPipeline(
  base: string,
  spans: readonly SanitizationSpan[],
  sanitized: readonly ProvenancedDatum<string>[],
): string {
  if (sanitized.length === 0) return applySanitizationSpans(base, spans);

  let current = applySanitizations(base, sanitized);
  const ordered = [...spans].sort(
    (a, b) => Number(b.replacement === "") - Number(a.replacement === "") || a.start - b.start,
  );
  for (const span of ordered) {
    const start = Math.min(Math.max(span.start, 0), base.length);
    const end = Math.min(Math.max(span.end, start), base.length);
    const source = base.slice(start, end);
    if (source.length > 0) current = current.split(source).join(span.replacement);
  }
  return current;
}
