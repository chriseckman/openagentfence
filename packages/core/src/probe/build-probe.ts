import { PROBE_SCRIPT_TEMPLATE } from "./probe-script.js";
import { PROBE_VERSION } from "./probe-result.js";

export interface ProbeBuildOptions {
  readonly maxNodes?: number;
  readonly maxTextLength?: number;
  readonly maxTextBytes?: number;
  readonly maxComments?: number;
  readonly maxMetadata?: number;
  readonly maxLinks?: number;
  readonly timeBudgetMs?: number;
}

export const DEFAULT_PROBE_OPTIONS: Required<ProbeBuildOptions> = {
  maxNodes: 2000,
  maxTextLength: 5000,
  maxTextBytes: 200_000,
  maxComments: 200,
  maxMetadata: 50,
  maxLinks: 500,
  timeBudgetMs: 50,
};

/**
 * Build the probe script string with the given resource caps. Values are
 * substituted as numeric literals only, so no code can be injected. The
 * resulting string is passed to `page.evaluate`/equivalent by adapters; the
 * host never evaluates it itself.
 */
export function buildProbeScript(options?: ProbeBuildOptions): string {
  const opts: Required<ProbeBuildOptions> = { ...DEFAULT_PROBE_OPTIONS, ...options };
  return PROBE_SCRIPT_TEMPLATE.replace("__MAX_NODES__", String(opts.maxNodes))
    .replace("__MAX_TEXT_LENGTH__", String(opts.maxTextLength))
    .replace("__MAX_TEXT_BYTES__", String(opts.maxTextBytes))
    .replace("__MAX_COMMENTS__", String(opts.maxComments))
    .replace("__MAX_METADATA__", String(opts.maxMetadata))
    .replace("__MAX_LINKS__", String(opts.maxLinks))
    .replace("__TIME_BUDGET__", String(opts.timeBudgetMs))
    .replace("__PROBE_VERSION__", String(PROBE_VERSION));
}

/** Default probe with standard resource caps. */
export const PROBE_SCRIPT: string = buildProbeScript();
