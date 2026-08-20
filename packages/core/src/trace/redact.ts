import { createHash } from "node:crypto";
import { egressMatchForms, MAX_EGRESS_VALUE_BYTES } from "../egress/match.js";

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

/**
 * Bounded, documented textual representations checked at public artifact
 * boundaries. This deliberately excludes heuristic transformations that could
 * create false positives or unbounded expansion.
 */
export function secretRedactionForms(value: string): readonly string[] {
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
  const base64Url = base64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  if (base64Url !== value) forms.push(base64Url);
  const nfkc = value.normalize("NFKC");
  if (nfkc !== value && nfkc.length > 0) forms.push(nfkc);
  const nfd = value.normalize("NFD");
  if (nfd !== value && nfd.length > 0) forms.push(nfd);
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
  private readonly egressNeedles = new Map<string, Set<string>>();

  registerSecret(value: string): void {
    if (value.length === 0) {
      return;
    }
    if (this.exact.has(value)) {
      return;
    }
    this.exact.add(value);
    for (const form of [value, ...secretRedactionForms(value)]) {
      if (form.length > 0 && !this.needles.includes(form)) {
        this.needles.push(form);
      }
    }
    this.needles.sort((a, b) => b.length - a.length);
    this.hashes.add(hash(value));
    const fingerprint = hash(value);
    for (const form of egressMatchForms(value)) {
      let fingerprints = this.egressNeedles.get(form);
      if (fingerprints === undefined) {
        fingerprints = new Set();
        this.egressNeedles.set(form, fingerprints);
      }
      fingerprints.add(fingerprint);
    }
  }

  /** True when the given value has been registered as a secret. */
  isSecret(value: string): boolean {
    return this.exact.has(value);
  }

  /** True if a string contains an exact or documented normalized secret form. */
  containsSecret(value: string): boolean {
    return this.needles.some((needle) => value.includes(needle));
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

  /** Match only the narrower D-11 egress forms; trace redaction remains broader. */
  matchEgress(
    value: string,
    signal?: AbortSignal,
  ): {
    readonly fingerprints: readonly string[];
    readonly incomplete: boolean;
  } {
    if (signal?.aborted === true || Buffer.byteLength(value, "utf8") > MAX_EGRESS_VALUE_BYTES) {
      return { fingerprints: [], incomplete: true };
    }
    const matches = new Set<string>();
    for (const [needle, fingerprints] of this.egressNeedles) {
      if (isAborted(signal)) return { fingerprints: [], incomplete: true };
      if (value.includes(needle)) for (const fingerprint of fingerprints) matches.add(fingerprint);
    }
    return { fingerprints: [...matches], incomplete: false };
  }
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}

/** SHA-256 hex digest, used for content hashes and secret fingerprints. */
export function hash(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
