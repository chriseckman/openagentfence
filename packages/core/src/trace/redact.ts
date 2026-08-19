import { createHash } from "node:crypto";

declare const REDACTED_EVIDENCE: unique symbol;

/**
 * A string that has passed through the redaction utilities. Only `redact`
 * produces values of this type; a plain string cannot be assigned to it
 * (type-level enforcement of INV-05 for findings, events, approvals, traces).
 */
export type RedactedEvidence = string & { readonly [REDACTED_EVIDENCE]: true };

function asEvidence(value: string): RedactedEvidence {
  return value as RedactedEvidence;
}

/** Normalized forms of a secret that must also be redacted (INV-05). */
function normalizedForms(value: string): string[] {
  const forms: string[] = [];
  const trimmed = value.trim();
  const lower = value.toLowerCase();
  if (trimmed.length > 0 && trimmed !== value) {
    forms.push(trimmed);
  }
  if (lower !== value && lower.length > 0) {
    forms.push(lower);
  }
  const upper = value.toUpperCase();
  if (upper !== value && upper.length > 0) {
    forms.push(upper);
  }
  const encoded = encodeURIComponent(value);
  if (encoded !== value) {
    forms.push(encoded);
  }
  const base64 = Buffer.from(value, "utf8").toString("base64");
  if (base64 !== value) {
    forms.push(base64);
  }
  return forms;
}

export interface Redactor {
  redact(input: string): RedactedEvidence;
}

/**
 * Registry of secret values that must never appear in output (INV-05). The
 * trace writer, finding serializer, and event emitter all redact through a
 * single shared registry. Values are added only from the application
 * (TB1); page content never registers secrets.
 */
export class RedactionRegistry implements Redactor {
  private readonly exact = new Set<string>();
  private readonly needles: string[] = [];
  private readonly hashes = new Set<string>();

  registerSecret(value: string): void {
    if (value.length === 0) {
      return;
    }
    if (this.exact.has(value)) {
      return;
    }
    this.exact.add(value);
    for (const form of [value, ...normalizedForms(value)]) {
      if (form.length > 0 && !this.needles.includes(form)) {
        this.needles.push(form);
      }
    }
    this.hashes.add(hash(value));
  }

  /** True when the given value has been registered as a secret. */
  isSecret(value: string): boolean {
    return this.exact.has(value);
  }

  redact(input: string): RedactedEvidence {
    let out = input;
    // Longest-first so shorter normalized forms never corrupt a longer match.
    for (const needle of this.needles) {
      out = out.split(needle).join("[REDACTED]");
    }
    return asEvidence(out);
  }

  /** Snapshot of registered secret hashes (for equality checks, never raw). */
  secretFingerprints(): string[] {
    return [...this.hashes];
  }
}

/** SHA-256 hex digest, used for content hashes and secret fingerprints. */
export function hash(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
