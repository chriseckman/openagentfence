import type { ScannerVerdict } from "../contracts/verdict.js";
import type { Severity } from "../contracts/finding.js";
import type { ScanResult } from "../contracts/scan-result.js";
import type { SecurityContext } from "./context.js";
import type { PluginManifest, ScannerPermission } from "./manifest.js";
import type { ScopedContextView } from "./context.js";
import type { DetectorTier } from "../guard/tier.js";

/**
 * Scanner contract (PRD §11 + `kind`). `kind` is required so the aggregator can
 * apply precedence and a semantic scanner can never be treated as
 * deterministic. `tier` is the detector tier (OAF-CORE-018); it is resolved
 * and validated by `defineScanner` (`tier0` = deterministic, `tier1`/`tier2` =
 * semantic). Scanners declare phases, an optional priority (lower runs
 * first), an optional timeout, and the context permissions they require.
 */
export interface SecurityScanner {
  readonly id: string;
  readonly phases: readonly import("../contracts/phase.js").SecurityPhase[];
  readonly kind: "deterministic" | "semantic";
  readonly tier?: DetectorTier;
  readonly priority?: number;
  readonly timeoutMs?: number;
  /** Availability is required before later high-impact session actions. */
  readonly required?: boolean;
  readonly permissions?: readonly ScannerPermission[];
  scan(ctx: SecurityContext): Promise<ScanResult>;
}

/**
 * Explicit least-privilege plugin registration input (INV-15). The plugin
 * callback receives only a manifest-scoped view; the full `SecurityContext`
 * remains inaccessible through this contract.
 */
export interface PluginSecurityScannerDefinition {
  readonly id: string;
  readonly phases: readonly import("../contracts/phase.js").SecurityPhase[];
  readonly kind: "deterministic" | "semantic";
  readonly tier?: DetectorTier;
  readonly priority?: number;
  readonly timeoutMs?: number;
  readonly required?: boolean;
  readonly manifest: PluginManifest;
  scan(ctx: ScopedContextView): Promise<ScanResult>;
}

export type { ScannerVerdict, Severity, ScanResult };
