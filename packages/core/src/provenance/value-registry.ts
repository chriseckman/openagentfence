import { validateDataProvenance, type DataProvenance } from "../contracts/provenance.js";
import { egressMatchForms, MAX_EGRESS_VALUE_BYTES } from "../egress/match.js";
import { hash } from "../trace/redact.js";

export const DEFAULT_SOURCE_VALUE_LIMITS = Object.freeze({
  maxEntries: 256,
  maxProvenancesPerEntry: 8,
  maxMatchedSources: 64,
  maxTotalFormBytes: 4 * 1024 * 1024,
  maxValueBytes: MAX_EGRESS_VALUE_BYTES,
  ttlMs: 30 * 60 * 1000,
});

export interface SourceValueRegistryLimits {
  readonly maxEntries: number;
  readonly maxProvenancesPerEntry: number;
  readonly maxMatchedSources: number;
  readonly maxTotalFormBytes: number;
  readonly maxValueBytes: number;
  readonly ttlMs: number;
}

export interface SourceValueEvidence {
  readonly fingerprint: string;
  readonly provenance: DataProvenance;
}

export interface SourceValueMatch {
  readonly fingerprints: readonly string[];
  readonly sources: readonly SourceValueEvidence[];
  readonly incomplete: boolean;
}

export type SourceValueRegistration = "registered" | "duplicate" | "incomplete";

interface Entry {
  readonly fingerprint: string;
  readonly forms: readonly string[];
  readonly provenances: DataProvenance[];
  readonly expiresAt: number;
  readonly formBytes: number;
}

/**
 * Session-private, bounded value registry for v0.1 coarse source-to-sink
 * matching. Raw/normalized forms are retained only in this non-serializable
 * object; public evidence contains a SHA-256 fingerprint and provenance.
 */
export class SourceValueRegistry {
  private readonly entries = new Map<string, Entry>();
  private totalFormBytes = 0;
  private exhausted = false;

  constructor(
    private readonly limits: SourceValueRegistryLimits = DEFAULT_SOURCE_VALUE_LIMITS,
    private readonly now: () => number = Date.now,
  ) {
    for (const [name, value] of Object.entries(limits)) {
      if (!Number.isFinite(value) || value < 1) {
        throw new TypeError(`source value registry ${name} must be positive`);
      }
    }
  }

  register(
    value: string,
    provenance: DataProvenance,
    signal?: AbortSignal,
  ): SourceValueRegistration {
    this.prune();
    const validated = validateDataProvenance(provenance);
    const valueBytes = Buffer.byteLength(value, "utf8");
    if (
      this.exhausted ||
      isSignalAborted(signal) ||
      validated === null ||
      value.length === 0 ||
      valueBytes > this.limits.maxValueBytes
    ) {
      this.exhausted = true;
      return "incomplete";
    }

    const fingerprint = hash(value);
    const existing = this.entries.get(fingerprint);
    if (existing !== undefined) {
      if (!existing.provenances.some((item) => sameProvenance(item, validated))) {
        if (existing.provenances.length >= this.limits.maxProvenancesPerEntry) {
          this.exhausted = true;
          return "incomplete";
        }
        existing.provenances.push(validated);
      }
      return "duplicate";
    }

    const forms = egressMatchForms(value);
    const formBytes = forms.reduce((total, form) => total + Buffer.byteLength(form, "utf8"), 0);
    if (
      this.entries.size >= this.limits.maxEntries ||
      this.totalFormBytes + formBytes > this.limits.maxTotalFormBytes
    ) {
      this.exhausted = true;
      return "incomplete";
    }
    this.entries.set(fingerprint, {
      fingerprint,
      forms,
      provenances: [validated],
      expiresAt: this.now() + this.limits.ttlMs,
      formBytes,
    });
    this.totalFormBytes += formBytes;
    return "registered";
  }

  match(value: string, signal?: AbortSignal): SourceValueMatch {
    this.prune();
    if (
      this.exhausted ||
      isSignalAborted(signal) ||
      Buffer.byteLength(value, "utf8") > this.limits.maxValueBytes
    ) {
      return { fingerprints: [], sources: [], incomplete: true };
    }
    const fingerprints = new Set<string>();
    const sources: SourceValueEvidence[] = [];
    for (const entry of this.entries.values()) {
      if (isSignalAborted(signal)) return { fingerprints: [], sources: [], incomplete: true };
      if (!entry.forms.some((form) => value.includes(form))) continue;
      fingerprints.add(entry.fingerprint);
      for (const provenance of entry.provenances) {
        if (sources.length >= this.limits.maxMatchedSources) {
          return { fingerprints: [], sources: [], incomplete: true };
        }
        sources.push({ fingerprint: entry.fingerprint, provenance });
      }
    }
    return { fingerprints: [...fingerprints], sources, incomplete: false };
  }

  get size(): number {
    this.prune();
    return this.entries.size;
  }

  get incomplete(): boolean {
    return this.exhausted;
  }

  clear(): void {
    this.entries.clear();
    this.totalFormBytes = 0;
    this.exhausted = false;
  }

  private prune(): void {
    const now = this.now();
    for (const [fingerprint, entry] of this.entries) {
      if (entry.expiresAt > now) continue;
      this.entries.delete(fingerprint);
      this.totalFormBytes -= entry.formBytes;
    }
  }
}

function sameProvenance(a: DataProvenance, b: DataProvenance): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function isSignalAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}
