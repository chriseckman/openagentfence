import {
  defineScanner,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { scanInjection } from "../injection-heuristics/rules.js";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

/**
 * ARIA / DOM consistency scanner (OAF-BROWSER-007). Detects instruction-like
 * accessibility content in `aria-label` / `aria-description` and accessibility
 * text not meaningfully connected to visible content.
 */
export function createAriaScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "aria",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) {
        return {
          scanner: "aria",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      }
      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];

      for (const node of probe.nodes) {
        const candidate = [node.ariaLabel, node.ariaDescription].filter(
          (v): v is string => v !== null && v.trim().length > 0,
        );
        if (candidate.length === 0) {
          continue;
        }
        const text = candidate.join(" ");
        for (const match of scanInjection(text)) {
          findings.push(
            makeFinding(ctx, {
              id: `aria:${node.selector}:${match.ruleId}`,
              category: "aria_instruction",
              title: "Instruction-like accessibility content",
              description: `Accessibility-only content (${match.category}) on a node without matching visible text`,
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
        scanner: "aria",
        kind: "deterministic",
        verdict: findings.length > 0 ? "warn" : "allow",
        severity: findings.length > 0 ? "high" : "info",
        findings,
      };
    },
  });
}
