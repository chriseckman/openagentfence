import {
  defineScanner,
  hostnameOf,
  isPrivateNetworkDestination,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

/** Suspicious-link scanner (OAF-BROWSER-011): schemes, private-network targets, text-vs-href mismatch. */
export function createUrlScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "url",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) {
        return {
          scanner: "url",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      }
      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];

      probe.links.forEach((link, index) => {
        const href = link.href;
        const resolvedHref = resolveHref(href, origin);
        const scheme = href.match(/^([a-z][a-z0-9+.-]*):/i)?.[1]?.toLowerCase();
        const hasNetworkAuthority =
          scheme === "http" || scheme === "https" || href.startsWith("//");
        if (scheme !== undefined && scheme !== "http" && scheme !== "https") {
          findings.push(
            makeFinding(ctx.redactor, {
              id: `url:${index}:unsafe-scheme`,
              category: "unsafe_scheme_link",
              title: "Unsafe URL scheme in link",
              description: `Link uses a scriptable or data scheme: ${href.slice(0, 60)}`,
              sourceType: "dom",
              origin,
              evidence: href.slice(0, 200),
              recommendedAction: "warn",
              severity: "medium",
            }),
          );
          return;
        }
        if (hasNetworkAuthority && isPrivateNetworkDestination(resolvedHref)) {
          findings.push(
            makeFinding(ctx.redactor, {
              id: `url:${index}:private`,
              category: "private_network_link",
              title: "Link to a private/local network address",
              description: `Link targets a private or metadata destination: ${href.slice(0, 60)}`,
              sourceType: "dom",
              origin,
              evidence: href.slice(0, 200),
              recommendedAction: "warn",
              severity: "high",
            }),
          );
        }

        const hrefHost = hostnameOf(resolvedHref);
        const textHost = hostnameOf(link.text);
        if (
          hrefHost !== null &&
          textHost !== null &&
          hrefHost !== textHost &&
          link.text.trim().length > 0
        ) {
          findings.push(
            makeFinding(ctx.redactor, {
              id: `url:${index}:mismatch`,
              category: "link_text_host_mismatch",
              title: "Link text and destination host differ",
              description: `Displayed host "${textHost}" does not match destination host "${hrefHost}"`,
              sourceType: "dom",
              origin,
              evidence: `text: ${link.text.slice(0, 100)} | href: ${href.slice(0, 100)}`,
              recommendedAction: "warn",
              severity: "medium",
            }),
          );
        }
      });

      return {
        scanner: "url",
        kind: "deterministic",
        verdict: findings.length > 0 ? "warn" : "allow",
        severity: findings.length > 0 ? "medium" : "info",
        findings,
      };
    },
  });
}

function resolveHref(href: string, origin: string): string {
  try {
    return new URL(href, origin).toString();
  } catch {
    return href;
  }
}
