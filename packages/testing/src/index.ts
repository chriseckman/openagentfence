/**
 * The package name of this library.
 * @public
 */
export const PACKAGE_NAME = "@openagentfence/testing";

export { startFixtureServer, fixtureSentinel } from "./fixture-server.js";
export type { FixtureOrigin, CapturedRequest, FixtureServer } from "./fixture-server.js";

export {
  CORPUS_SCHEMA_VERSION,
  validateCorpusCase,
  corpusHash,
  loadCorpusDocument,
  loadCorpusFile,
} from "./corpus.js";
export type {
  CorpusCase,
  CorpusMode,
  CorpusKind,
  CorpusPage,
  CorpusExpected,
  LoadedCorpus,
} from "./corpus.js";

export {
  expectNoRawSecret,
  hasFindingCategory,
  isBlockingVerdict,
  reasonsOf,
} from "./assertions.js";
