import type { SecurityScanner } from "./scanner.js";
import type { PluginSecurityScannerDefinition } from "./scanner.js";
import { SECURITY_PHASES } from "../contracts/phase.js";
import { kindForTier, defaultTierForKind } from "../guard/tier.js";
import { buildScopedView } from "./context.js";
import { SCANNER_PERMISSIONS } from "./manifest.js";

const scopedPluginScanners = new WeakSet<SecurityScanner>();

/**
 * Register a scanner (PRD §11). Registration is explicit — an import of
 * `defineScanner` — never name-based loading (INV-16, no arbitrary code
 * execution). Resolves and validates the detector tier (OAF-CORE-018) and
 * returns a frozen scanner definition.
 */
export function defineScanner(scanner: SecurityScanner): Readonly<SecurityScanner> {
  if (scanner.permissions !== undefined) {
    throw new TypeError("permissions require definePluginScanner");
  }
  return validateAndFreeze(scanner);
}

/**
 * Register a plugin through a mandatory manifest-scoped wrapper. P0 does not
 * provide a network sandbox, so plugins requesting outbound network access
 * fail closed until the P1 sandbox exists.
 */
export function definePluginScanner(
  plugin: PluginSecurityScannerDefinition,
): Readonly<SecurityScanner> {
  validatePluginManifest(plugin);
  const scanner = validateAndFreeze({
    id: plugin.id,
    phases: plugin.phases,
    kind: plugin.kind,
    ...(plugin.tier === undefined ? {} : { tier: plugin.tier }),
    ...(plugin.priority === undefined ? {} : { priority: plugin.priority }),
    ...(plugin.timeoutMs === undefined ? {} : { timeoutMs: plugin.timeoutMs }),
    ...(plugin.required === undefined ? {} : { required: plugin.required }),
    permissions: Object.freeze([...plugin.manifest.permissions]),
    scan: async (ctx) => plugin.scan(buildScopedView(ctx, plugin.manifest.permissions)),
  });
  scopedPluginScanners.add(scanner);
  return scanner;
}

/** Internal registry guard: permissions may only come from the scoped wrapper. */
export function isScopedPluginScanner(scanner: SecurityScanner): boolean {
  return scanner.permissions === undefined || scopedPluginScanners.has(scanner);
}

function validateAndFreeze(scanner: SecurityScanner): Readonly<SecurityScanner> {
  if (scanner.id.trim().length === 0) {
    throw new TypeError("scanner id must be a non-empty string");
  }
  if (scanner.phases.length === 0) {
    throw new TypeError(`scanner ${scanner.id} must declare at least one phase`);
  }
  for (const phase of scanner.phases) {
    if (!(SECURITY_PHASES as readonly string[]).includes(phase)) {
      throw new TypeError(`scanner ${scanner.id} has invalid phase: ${phase}`);
    }
  }
  const kind: string = scanner.kind;
  if (kind !== "deterministic" && kind !== "semantic") {
    throw new TypeError(`scanner ${scanner.id} has invalid kind: ${kind}`);
  }
  const tier = scanner.tier ?? defaultTierForKind(kind);
  if (kindForTier(tier) !== kind) {
    throw new TypeError(
      `scanner ${scanner.id} declares tier ${tier}, which requires kind ${kindForTier(tier)}`,
    );
  }
  return Object.freeze({ ...scanner, tier });
}

function validatePluginManifest(plugin: PluginSecurityScannerDefinition): void {
  const manifest = plugin.manifest;
  if (manifest.id !== plugin.id || manifest.id.trim().length === 0) {
    throw new TypeError("plugin manifest id must match scanner id");
  }
  if (manifest.network) {
    throw new TypeError("plugin network access is unavailable without the P1 sandbox");
  }
  const unique = new Set(manifest.permissions);
  if (
    unique.size !== manifest.permissions.length ||
    manifest.permissions.some(
      (permission) => !(SCANNER_PERMISSIONS as readonly string[]).includes(permission),
    )
  ) {
    throw new TypeError("plugin manifest permissions must be unique and supported");
  }
}
