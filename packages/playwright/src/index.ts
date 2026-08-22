/**
 * @packageDocumentation
 * Guarded Playwright adapter APIs for the experimental v0.1 line.
 * @experimental
 */

export {
  describePlaywrightCapabilities,
  playwrightAdapter,
  PLAYWRIGHT_NETWORK_CAPABILITIES,
} from "./adapter.js";
export { PlaywrightRevalidationError } from "./adapter.js";
export type { PlaywrightAdapterOptions } from "./adapter.js";
export { wrapPage } from "./wrap.js";
export { currentState } from "./wrap.js";
export { PlaywrightHelperRegistry } from "./helpers.js";
export type {
  PlaywrightOperation,
  PlaywrightUploadFile,
  UploadOptions,
  DownloadMetadata,
  SecureLocator,
  SecurePage,
} from "./wrap.js";
export type { HelperArgument, PlaywrightHelperDefinition } from "./helpers.js";
