import type { ScannerVerdict } from "../contracts/verdict.js";
import type { Severity } from "../contracts/finding.js";
import type { ScanResult } from "../contracts/scan-result.js";
import type { SecurityContext } from "./context.js";
import type { ScannerPermission } from "./manifest.js";
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
  readonly permissions?: readonly ScannerPermission[];
  scan(ctx: SecurityContext): Promise<ScanResult>;
}

export type { ScannerVerdict, Severity, ScanResult };
