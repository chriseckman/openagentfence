// Dependency-direction rules for the OpenAgentFence monorepo.
//
// Source of truth: docs/ARCHITECTURE.md §3 ("Dependency rules"). `core` is the
// leaf; no package may import a package above it in the diagram; adapters
// never import `scanners` or `policy`; nothing imports `cli`.

/** Allowed `@openagentfence/*` dependencies per package, by short name. */
export const ALLOWED_DEPENDENCIES = {
  core: [],
  policy: ["core"],
  vault: ["core"],
  scanners: ["core"],
  providers: ["core"],
  playwright: ["core"],
  stagehand: ["core", "playwright"],
  testing: ["core", "scanners", "policy"],
  cli: ["core", "policy", "scanners", "testing", "providers", "vault", "playwright"],
};

const PACKAGE_NAMES = Object.keys(ALLOWED_DEPENDENCIES);

/**
 * Validate a map of `packageShortName -> string[] of @openagentfence/* short
 * names` (both declared dependencies and source imports).
 *
 * @param {Record<string, string[]>} packages
 * @returns {{ package: string; dependency: string; reason: string }[]}
 */
export function dependencyViolations(packages) {
  const violations = [];
  for (const [pkg, deps] of Object.entries(packages)) {
    const allowed = ALLOWED_DEPENDENCIES[pkg];
    if (allowed === undefined) {
      violations.push({
        package: pkg,
        dependency: "(package itself)",
        reason: `unknown package; expected one of: ${PACKAGE_NAMES.join(", ")}`,
      });
      continue;
    }
    for (const dep of deps) {
      if (dep === pkg) {
        continue;
      }
      if (!PACKAGE_NAMES.includes(dep)) {
        violations.push({
          package: pkg,
          dependency: dep,
          reason: `not an @openagentfence/* package`,
        });
        continue;
      }
      if (!allowed.includes(dep)) {
        violations.push({
          package: pkg,
          dependency: dep,
          reason: `not allowed; allowed for ${pkg}: ${allowed.join(", ") || "(none)"}`,
        });
      }
    }
  }
  return violations;
}
