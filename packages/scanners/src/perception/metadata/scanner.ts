import {
  defineScanner,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { scanInjection } from "../injection-heuristics/rules.js";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

/** Metadata / JSON-LD scanner (meta tags, OpenGraph, JSON-LD, title) (OAF-BROWSER-008). */
export function createMetadataScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "metadata",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) {
        return {
          scanner: "metadata",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      }
      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];
      const sources: Array<[string, string]> = [["title", probe.metadata.title]];
      for (const [key, value] of Object.entries(probe.metadata.meta)) {
        sources.push([`meta:${key}`, value]);
      }
      probe.metadata.jsonLd.forEach((json, index) => {
        sources.push([`json-ld:${index}`, json]);
      });
      probe.metadata.noscript.forEach((text, index) => {
        sources.push([`noscript:${index}`, text]);
      });

      for (const [label, text] of sources) {
        for (const match of scanInjection(text)) {
          findings.push(
            makeFinding(ctx, {
              id: `metadata:${label}:${match.ruleId}`,
              category: "metadata_instruction",
              title: "Instruction-like content in page metadata",
              description: `${label} contains ${match.category}`,
              sourceType: "dom",
              origin,
              evidence: match.evidence,
              recommendedAction: "block",
              severity: "high",
            }),
          );
        }
      }

      return {
        scanner: "metadata",
        kind: "deterministic",
        verdict: findings.length > 0 ? "warn" : "allow",
        severity: findings.length > 0 ? "high" : "info",
        findings,
      };
    },
  });
}
