import {
  defineScanner,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { classifyObservation, isHiddenClass, visibleText } from "../visibility/classify.js";
import { scanInjection } from "../injection-heuristics/rules.js";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

/**
 * Hidden DOM scanner (OAF-BROWSER-006). Extracts text from hidden/offscreen/
 * zero-size/accessibility-only nodes, flags instruction-like content, and
 * returns a sanitized representation that excludes hidden text.
 */
export function createHiddenDomScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "hidden-dom",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) {
        return {
          scanner: "hidden-dom",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      }
      const classified = classifyObservation(probe);
      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];

      for (const c of classified.nodes) {
        if (!isHiddenClass(c.visibility)) {
          continue;
        }
        const text = c.node.text.trim();
        if (text.length === 0) {
          continue;
        }
        for (const match of scanInjection(text)) {
          findings.push(
            makeFinding(ctx.redactor, {
              id: `hidden-dom:${c.node.selector}:${match.ruleId}`,
              category: "hidden_dom_instruction",
              title: "Instruction-like content in hidden DOM",
              description: `Hidden node (${c.visibility}) contains ${match.category}`,
              sourceType: "dom",
              selector: c.node.selector,
              frameOrigin: c.node.frameOrigin,
              origin,
              evidence: match.evidence,
              recommendedAction: "block",
              severity: "high",
            }),
          );
        }
      }

      const sanitized = visibleText(classified);
      return {
        scanner: "hidden-dom",
        kind: "deterministic",
        verdict: findings.length > 0 ? "sanitize" : "allow",
        severity: findings.length > 0 ? "high" : "info",
        findings,
        sanitized,
      };
    },
  });
}
