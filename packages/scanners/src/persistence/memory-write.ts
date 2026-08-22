import {
  defineScanner,
  type Finding,
  type SanitizationSpan,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { makeFinding } from "../helpers.js";
import { scanInjection } from "../perception/injection-heuristics/rules.js";

export const MEMORY_WRITE_SCAN_LIMITS = Object.freeze({
  maxBytes: 100 * 1024,
  maxMatches: 32,
  maxInstructionLength: 512,
});

interface InstructionRegion {
  readonly id: string;
  readonly start: number;
  readonly end: number;
}

const MEMORY_COMMAND =
  /\bremember\s*:\s*(?:always\s+)?(?:send|email|message|forward|upload|navigate|visit|open|delete|publish)\b[^\r\n]{0,512}/gi;

/** Deterministic PERSISTENCE instruction/data separator (INV-07). */
export function createMemoryWriteScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "memory-write",
    phases: ["PERSISTENCE"],
    kind: "deterministic",
    priority: 5,
    timeoutMs: 50,
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      if (
        ctx.payload.kind !== "memoryCandidate" ||
        typeof ctx.payload.candidate.value !== "string"
      ) {
        return clean();
      }
      const text = ctx.payload.candidate.value;
      const provenance = ctx.payload.candidate.provenance;
      if (ctx.signal.aborted || Date.now() >= ctx.deadline) return incomplete(ctx, "cancelled");
      if (Buffer.byteLength(text, "utf8") > MEMORY_WRITE_SCAN_LIMITS.maxBytes) {
        return incomplete(ctx, "oversized");
      }

      const regions: InstructionRegion[] = scanInjection(text).map((match) => ({
        id: match.ruleId,
        start: match.start,
        end: match.end,
      }));
      MEMORY_COMMAND.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = MEMORY_COMMAND.exec(text)) !== null) {
        if (Date.now() >= ctx.deadline) return incomplete(ctx, "cancelled");
        regions.push({
          id: "persistent_command",
          start: match.index,
          end: match.index + match[0].length,
        });
        if (regions.length >= MEMORY_WRITE_SCAN_LIMITS.maxMatches) {
          return incomplete(ctx, "match_limit");
        }
      }
      const bounded = dedupe(regions);
      if (bounded.length >= MEMORY_WRITE_SCAN_LIMITS.maxMatches) {
        return incomplete(ctx, "match_limit");
      }
      if (bounded.length === 0) return clean();

      const findings: Finding[] = bounded.map((region, index) =>
        makeFinding(ctx, {
          id: `memory-instruction:${region.id}:${index}`,
          category: "memory_instruction",
          title: "Instruction-like memory content removed",
          description:
            "A bounded deterministic rule separated instruction-like content from persistent data.",
          sourceType: "memory",
          provenance,
          evidence: `memory rule=${region.id}`,
          recommendedAction: "sanitize",
          severity: "high",
          confidence: 0.99,
        }),
      );
      const sanitizations: SanitizationSpan[] = bounded.map((region) => ({
        start: region.start,
        end: region.end,
        replacement: "[REMOVED:MEMORY_INSTRUCTION]",
        provenance,
      }));
      return {
        scanner: "memory-write",
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

function clean(): ScanResult {
  return {
    scanner: "memory-write",
    kind: "deterministic",
    verdict: "allow",
    severity: "info",
    findings: [],
  };
}

function incomplete(
  ctx: SecurityContext,
  reason: "cancelled" | "oversized" | "match_limit",
): ScanResult {
  return {
    scanner: "memory-write",
    kind: "deterministic",
    verdict: "block",
    severity: "critical",
    findings: [
      makeFinding(ctx, {
        id: `memory-write:${reason}`,
        category: "memory_scan_incomplete",
        title: "Memory scan incomplete",
        description: "The bounded memory instruction scan could not prove the candidate safe.",
        sourceType: "memory",
        provenance: ctx.provenance,
        evidence: `memory scanner ${reason}`,
        recommendedAction: "block",
        severity: "critical",
      }),
    ],
    metadata: { failureKind: reason },
  };
}

function dedupe(regions: readonly InstructionRegion[]): readonly InstructionRegion[] {
  const seen = new Set<string>();
  return regions
    .filter((region) => region.end > region.start)
    .sort((a, b) => a.start - b.start || b.end - a.end)
    .filter((region) => {
      const key = `${region.start}:${region.end}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}
