import type { SecurityScanner } from "@openagentfence/core";

import { createHiddenDomScanner } from "./perception/hidden-dom/scanner.js";
import { createAriaScanner } from "./perception/aria/scanner.js";
import { createCommentScanner } from "./perception/comments/scanner.js";
import { createAttributeScanner } from "./perception/attributes/scanner.js";
import { createMetadataScanner } from "./perception/metadata/scanner.js";
import { createEncodedPayloadScanner } from "./perception/encoded-payload/scanner.js";
import { createUnicodeInvisibleScanner } from "./perception/unicode-invisible/scanner.js";
import { createUrlScanner } from "./perception/url/scanner.js";
import { createCrossOriginNavigationScanner } from "./pre-action/cross-origin-navigation.js";
import { createLocalNetworkSsrfScanner } from "./pre-action/local-network-ssrf.js";
import { createFileEffectIntegrityScanner } from "./pre-action/file-effect-integrity.js";

/** The P0 PERCEPTION scanner catalog in priority order (ARCHITECTURE §6). */
export function defaultScanners(): SecurityScanner[] {
  return [
    createEncodedPayloadScanner(),
    createUnicodeInvisibleScanner(),
    createHiddenDomScanner(),
    createAriaScanner(),
    createCommentScanner(),
    createAttributeScanner(),
    createMetadataScanner(),
    createUrlScanner(),
    createCrossOriginNavigationScanner(),
    createLocalNetworkSsrfScanner(),
    createFileEffectIntegrityScanner(),
  ];
}

export {
  createHiddenDomScanner,
  createAriaScanner,
  createCommentScanner,
  createAttributeScanner,
  createMetadataScanner,
  createEncodedPayloadScanner,
  createUnicodeInvisibleScanner,
  createUrlScanner,
  createCrossOriginNavigationScanner,
  createLocalNetworkSsrfScanner,
  createFileEffectIntegrityScanner,
};

export {
  VISIBILITY_CLASSES,
  classifyNode,
  classifyObservation,
  visibleText,
  isHiddenClass,
  isVisibleClass,
} from "./perception/visibility/classify.js";
export type {
  VisibilityClass,
  ClassifiedNode,
  ClassifiedObservation,
} from "./perception/visibility/classify.js";

export {
  scanInjection,
  validateRulePack,
  ENGLISH_RULES,
} from "./perception/injection-heuristics/rules.js";
export type { InjectionRule, InjectionMatch } from "./perception/injection-heuristics/rules.js";

export {
  decodeBase64,
  decodeHex,
  decodeUrlEncoded,
  decodeHtmlEntities,
  decodeIterative,
} from "./normalize/decoders.js";
export type { DecodeOutcome } from "./normalize/decoders.js";
export { stripZeroWidth, foldHomoglyphs, fold } from "./normalize/fold.js";
export { DEFAULT_DECODE_LIMITS } from "./normalize/limits.js";
export type { DecodeLimits } from "./normalize/limits.js";
