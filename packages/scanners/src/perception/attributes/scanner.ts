import {
  defineScanner,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { scanInjection } from "../injection-heuristics/rules.js";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

/** Instruction-bearing attribute scanner (title, alt, placeholder, data-*) (OAF-BROWSER-008). */
export function createAttributeScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "attributes",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) {
        return {
          scanner: "attributes",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      }
      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];
      for (const node of probe.nodes) {
        for (const [attr, value] of Object.entries(node.attributes)) {
          if (value.trim().length === 0) {
            continue;
          }
          for (const match of scanInjection(value)) {
            findings.push(
              makeFinding(ctx, {
                id: `attributes:${node.selector}:${attr}:${match.ruleId}`,
                category: "attribute_instruction",
                title: "Instruction-like content in element attribute",
                description: `Attribute "${attr}" contains ${match.category}`,
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
      }
      return {
        scanner: "attributes",
        kind: "deterministic",
        verdict: findings.length > 0 ? "warn" : "allow",
        severity: findings.length > 0 ? "high" : "info",
        findings,
      };
    },
  });
}
