/**
 * @packageDocumentation
 * Verified Stagehand 4.0.1 adapter APIs for the experimental v0.1 line.
 * @experimental
 */

export {
  stagehandAdapter,
  authorizeActions,
  wrapStagehand,
  normalizeObserveResult,
  StagehandSecurityError,
  STAGEHAND_SECURITY_ERROR_CODES,
  STAGEHAND_SURFACE_COVERAGE,
  STAGEHAND_NETWORK_CAPABILITIES,
} from "./adapter.js";
export type {
  StagehandAuthorizationResult,
  StagehandSecurityErrorCode,
  StagehandStateResolver,
  StagehandSurfaceStatus,
  StagehandWrapOptions,
} from "./adapter.js";
export type { StagehandLike, StagehandObserveResult, StagehandObserveResponse } from "./types.js";
