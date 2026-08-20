import {
  defineScanner,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { decodeIterative } from "../../normalize/decoders.js";
import { DEFAULT_DECODE_LIMITS } from "../../normalize/limits.js";
import { scanInjection } from "../injection-heuristics/rules.js";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

/**
 * Encoded payload normalizer (OAF-BROWSER-009). Iteratively decodes Base64 /
 * hex / URL / HTML-entity encodings (bounded), then scans the decoded payload
 * for injection patterns. Decoded instruction-like content is a finding.
 */
export function createEncodedPayloadScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "encoded-payload",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) {
        return {
          scanner: "encoded-payload",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      }
      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];

      for (const node of probe.nodes) {
        const text = node.text.trim();
        if (text.length === 0) {
          continue;
        }
        const decoded = decodeIterative(
          text,
          DEFAULT_DECODE_LIMITS.maxDecodeDepth,
          DEFAULT_DECODE_LIMITS.deadlineMs,
        );
        if (decoded.status === "refused") {
          findings.push(
            makeFinding(ctx, {
              id: `encoded:${node.selector}:limit:${decoded.reason ?? "unknown"}`,
              category: "encoded_payload_limit",
              title: "Encoded payload could not be safely normalized",
              description: `Encoded content exceeded the ${decoded.reason ?? "unknown"} bound and was not treated as clean.`,
              sourceType: "dom",
              selector: node.selector,
              frameOrigin: node.frameOrigin,
              origin,
              evidence: text.slice(0, 200),
              recommendedAction: "warn",
              severity: "medium",
            }),
          );
          continue;
        }
        if (decoded.status === "unchanged") {
          continue;
        }
        for (const match of scanInjection(decoded.text)) {
          findings.push(
            makeFinding(ctx, {
              id: `encoded:${node.selector}:${match.ruleId}`,
              category: "encoded_instruction",
              title: "Instruction-like content in encoded payload",
              description: `Decoded payload (${decoded.chain.join(" -> ")}) contains ${match.category}`,
              sourceType: "dom",
              selector: node.selector,
              frameOrigin: node.frameOrigin,
              origin,
              evidence: match.evidence,
              recommendedAction: "block",
              severity: "high",
            }),
          );
        }
      }

      return {
        scanner: "encoded-payload",
        kind: "deterministic",
        verdict: findings.length > 0 ? "warn" : "allow",
        severity: findings.length > 0 ? "high" : "info",
        findings,
      };
    },
  });
}
