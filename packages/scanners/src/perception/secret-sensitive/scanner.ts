import {
  defineScanner,
  hash,
  parseHandle,
  type Finding,
  type ScanResult,
  type SanitizationSpan,
  type SecurityContext,
} from "@openagentfence/core";
import { makeFinding } from "../../helpers.js";

export const SECRET_SCAN_LIMITS = Object.freeze({
  maxBytes: 100 * 1024,
  maxMatches: 32,
  maxCandidateLength: 4096,
});

export interface SecretPrefixPattern {
  readonly id: string;
  readonly prefix: string;
  readonly alphabet: "alphanumeric" | "base64url" | "hex";
  readonly minLength: number;
  readonly maxLength: number;
  readonly kind?: "SECRET" | "PII" | "CREDENTIAL";
}

/** Data-only policy-document shape accepted by {@link secretPatternsFromPolicy}. */
export interface PolicySecretPrefixPattern {
  readonly id: string;
  readonly prefix: string;
  readonly alphabet: "alphanumeric" | "base64url" | "hex";
  readonly min_length: number;
  readonly max_length: number;
  readonly kind?: "SECRET" | "PII" | "CREDENTIAL";
}

interface Match {
  readonly id: string;
  readonly kind: "SECRET" | "PII" | "CREDENTIAL";
  readonly start: number;
  readonly end: number;
}

const BUILT_INS: readonly SecretPrefixPattern[] = [
  { id: "aws_access_key", prefix: "AKIA", alphabet: "alphanumeric", minLength: 20, maxLength: 20 },
  { id: "github_token", prefix: "ghp_", alphabet: "alphanumeric", minLength: 40, maxLength: 255 },
  { id: "github_oauth", prefix: "gho_", alphabet: "alphanumeric", minLength: 40, maxLength: 255 },
  {
    id: "stripe_live_key",
    prefix: "sk_live_",
    alphabet: "alphanumeric",
    minLength: 32,
    maxLength: 255,
  },
];

/** Validate a closed, linear-time custom pattern. Arbitrary regex is not accepted. */
export function validateSecretPattern(input: SecretPrefixPattern): SecretPrefixPattern {
  if (!/^[a-z0-9_.-]{1,64}$/.test(input.id)) throw new TypeError("invalid secret pattern id");
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(input.prefix))
    throw new TypeError("invalid secret pattern prefix");
  if (!Number.isInteger(input.minLength) || !Number.isInteger(input.maxLength))
    throw new TypeError("secret pattern lengths must be integers");
  if (
    input.minLength < input.prefix.length ||
    input.maxLength < input.minLength ||
    input.maxLength > 4096
  ) {
    throw new RangeError("invalid secret pattern length bounds");
  }
  return Object.freeze({ ...input });
}

/** Convert policy entries to the scanner's runtime shape after validation. */
export function secretPatternsFromPolicy(
  patterns: readonly PolicySecretPrefixPattern[],
): readonly SecretPrefixPattern[] {
  return patterns.map((pattern) =>
    validateSecretPattern({
      id: pattern.id,
      prefix: pattern.prefix,
      alphabet: pattern.alphabet,
      minLength: pattern.min_length,
      maxLength: pattern.max_length,
      ...(pattern.kind === undefined ? {} : { kind: pattern.kind }),
    }),
  );
}

export function createSecretSensitiveScanner(
  additionalPatterns: readonly SecretPrefixPattern[] = [],
): ReturnType<typeof defineScanner> {
  if (additionalPatterns.length > 32) throw new RangeError("too many additional secret patterns");
  const patterns = [...BUILT_INS, ...additionalPatterns.map(validateSecretPattern)];
  return defineScanner({
    id: "secret-sensitive",
    phases: ["PERCEPTION", "MODEL_OUTPUT", "PERSISTENCE", "EGRESS"],
    kind: "deterministic",
    timeoutMs: 50,
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const text = textFromContext(ctx);
      if (text === null) return clean();
      if (Date.now() >= ctx.deadline) return unavailable(ctx, "cancelled");
      if (Buffer.byteLength(text, "utf8") > SECRET_SCAN_LIMITS.maxBytes)
        return unavailable(ctx, "oversized");

      // Opaque handles are inert references, not secret material. Mask only
      // valid handles while preserving offsets so a name/id such as
      // "password:<id>" cannot be rediscovered as a raw credential.
      const scannedText = maskOpaqueHandles(text);
      const matches: Match[] = [];
      for (const pattern of patterns) {
        scanPrefix(scannedText, pattern, matches, ctx);
        if (matches.length >= SECRET_SCAN_LIMITS.maxMatches) break;
      }
      scanAssignments(scannedText, matches, ctx);
      scanPrivateKeys(scannedText, matches);
      if (ctx.signal.aborted || Date.now() >= ctx.deadline) return unavailable(ctx, "cancelled");
      if (matches.length >= SECRET_SCAN_LIMITS.maxMatches) return unavailable(ctx, "match_limit");
      const bounded = dedupe(matches).slice(0, SECRET_SCAN_LIMITS.maxMatches);
      if (bounded.length === 0) return clean();

      const findings: Finding[] = bounded.map((match, index) =>
        makeFinding(ctx, {
          id: `secret:${match.id}:${index}`,
          category: "secret_detected",
          title: "Sensitive value detected",
          description: `A value matched the bounded ${match.id} detector and was replaced before release.`,
          sourceType: sourceType(ctx),
          provenance: ctx.provenance,
          evidence: `pattern=${match.id}; fingerprint=${hash(text.slice(match.start, match.end)).slice(0, 12)}`,
          recommendedAction: "sanitize",
          severity: "high",
          confidence: 0.99,
        }),
      );
      const sanitizations: SanitizationSpan[] = bounded.map((match) => ({
        start: match.start,
        end: match.end,
        replacement: `[[OAF_SENSITIVE:${match.kind}:${match.id}]]`,
        provenance: ctx.provenance,
      }));
      return {
        scanner: "secret-sensitive",
        kind: "deterministic",
        verdict: "sanitize",
        severity: "high",
        confidence: 0.99,
        findings,
        sanitizations,
      };
    },
  });
}

function maskOpaqueHandles(text: string): string {
  return text.replace(/<(?:SECRET|PII|CREDENTIAL):[^:>]+:[^:>]+>/g, (candidate) =>
    parseHandle(candidate) === null ? candidate : " ".repeat(candidate.length),
  );
}

function clean(): ScanResult {
  return {
    scanner: "secret-sensitive",
    kind: "deterministic",
    verdict: "allow",
    severity: "info",
    findings: [],
  };
}

function unavailable(
  ctx: SecurityContext,
  reason: "cancelled" | "oversized" | "match_limit",
): ScanResult {
  return {
    scanner: "secret-sensitive",
    kind: "deterministic",
    verdict: "sanitize",
    severity: "critical",
    findings: [
      makeFinding(ctx, {
        id: `secret-sensitive:${reason}`,
        category: "secret_scan_incomplete",
        title: "Sensitive-data scan incomplete",
        description: "The bounded sensitive-data scan could not prove the content safe.",
        sourceType: sourceType(ctx),
        evidence: `secret scanner ${reason}`,
        recommendedAction: "sanitize",
        severity: "critical",
      }),
    ],
    sanitized: { value: "[REDACTED:SENSITIVE_SCAN_INCOMPLETE]", provenance: ctx.provenance },
    metadata: { failureKind: reason },
  };
}

function textFromContext(ctx: SecurityContext): string | null {
  const payload = ctx.payload;
  if (payload.kind === "observation")
    return (
      payload.observation.ariaSnapshot ??
      payload.observation.probe?.nodes.map((node) => node.text).join("\n") ??
      ""
    );
  if (payload.kind === "modelOutput") return payload.output.content;
  if (payload.kind === "memoryCandidate" && typeof payload.candidate.value === "string")
    return payload.candidate.value;
  if (payload.kind === "egressPayload" && typeof payload.payload.value === "string")
    return payload.payload.value;
  return null;
}

function sourceType(ctx: SecurityContext): "dom" | "tool" | "memory" {
  if (ctx.payload.kind === "observation") return "dom";
  if (ctx.payload.kind === "memoryCandidate") return "memory";
  return "tool";
}

function scanPrefix(
  text: string,
  pattern: SecretPrefixPattern,
  out: Match[],
  ctx: SecurityContext,
): void {
  let from = 0;
  while (out.length < SECRET_SCAN_LIMITS.maxMatches) {
    if (ctx.signal.aborted || Date.now() >= ctx.deadline) return;
    const start = text.indexOf(pattern.prefix, from);
    if (start < 0) return;
    let end = start + pattern.prefix.length;
    while (
      end < text.length &&
      end - start < pattern.maxLength &&
      inAlphabet(text[end] ?? "", pattern.alphabet)
    )
      end += 1;
    const length = end - start;
    if (length >= pattern.minLength && boundedByDelimiter(text, start, end))
      out.push({ id: pattern.id, kind: pattern.kind ?? "SECRET", start, end });
    from = Math.max(end, start + 1);
  }
}

function scanAssignments(text: string, out: Match[], ctx: SecurityContext): void {
  const pattern =
    /\b(password|passwd|api[_-]?key|access[_-]?token|bearer)\s*[:=]\s*["']?([A-Za-z0-9._~+/-]{12,256})/gi;
  let match: RegExpExecArray | null;
  while (out.length < SECRET_SCAN_LIMITS.maxMatches && (match = pattern.exec(text)) !== null) {
    if (ctx.signal.aborted || Date.now() >= ctx.deadline) return;
    const value = match[2];
    if (value === undefined || /^(example|placeholder|changeme|not-a-secret)/i.test(value))
      continue;
    const relative = match[0].lastIndexOf(value);
    const start = match.index + relative;
    out.push({
      id: match[1]?.toLowerCase().replaceAll("-", "_") ?? "credential",
      kind: "CREDENTIAL",
      start,
      end: start + value.length,
    });
  }
}

function scanPrivateKeys(text: string, out: Match[]): void {
  const begin = "-----BEGIN PRIVATE KEY-----";
  const endMarker = "-----END PRIVATE KEY-----";
  const start = text.indexOf(begin);
  if (start < 0) return;
  const end = text.indexOf(endMarker, start + begin.length);
  if (end >= 0 && end + endMarker.length - start <= SECRET_SCAN_LIMITS.maxCandidateLength)
    out.push({ id: "private_key", kind: "CREDENTIAL", start, end: end + endMarker.length });
}

function inAlphabet(value: string, alphabet: SecretPrefixPattern["alphabet"]): boolean {
  if (alphabet === "hex") return /^[a-fA-F0-9]$/.test(value);
  if (alphabet === "base64url") return /^[A-Za-z0-9_-]$/.test(value);
  return /^[A-Za-z0-9]$/.test(value);
}

function boundedByDelimiter(text: string, start: number, end: number): boolean {
  return (
    (start === 0 || !/[A-Za-z0-9]/.test(text[start - 1] ?? "")) &&
    (end === text.length || !/[A-Za-z0-9]/.test(text[end] ?? ""))
  );
}

function dedupe(matches: readonly Match[]): Match[] {
  return [...matches]
    .sort((a, b) => a.start - b.start || b.end - a.end)
    .filter((match, index, all) => index === 0 || match.start >= (all[index - 1]?.end ?? 0));
}
