import {
  defineScanner,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { scanInjection } from "../injection-heuristics/rules.js";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

/** HTML comment scanner (OAF-BROWSER-008). */
export function createCommentScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "comments",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) {
        return {
          scanner: "comments",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      }
      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];
      probe.comments.forEach((comment, index) => {
        for (const match of scanInjection(comment)) {
          findings.push(
            makeFinding(ctx.redactor, {
              id: `comments:${index}:${match.ruleId}`,
              category: "comment_instruction",
              title: "Instruction-like content in HTML comment",
              description: `HTML comment contains ${match.category}`,
              sourceType: "dom",
              origin,
              evidence: match.evidence,
              recommendedAction: "block",
              severity: "high",
            }),
          );
        }
      });
      return {
        scanner: "comments",
        kind: "deterministic",
        verdict: findings.length > 0 ? "warn" : "allow",
        severity: findings.length > 0 ? "high" : "info",
        findings,
      };
    },
  });
}
