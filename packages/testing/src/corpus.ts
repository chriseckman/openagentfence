import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { hash, stableSerialize } from "@openagentfence/core";

/** Strict language-neutral corpus contract (OAF-TEST-002). */
export const CORPUS_SCHEMA_VERSION = "1.1.0";

export const CORPUS_LIMITS = Object.freeze({
  maxFileBytes: 4 * 1024 * 1024,
  maxCases: 4_096,
  maxDepth: 16,
  maxStringBytes: 4_096,
  maxTaskBytes: 16_384,
  maxArrayItems: 128,
  maxPages: 16,
  maxSteps: 64,
  maxFixtureBytes: 1024 * 1024,
});

export const CORPUS_ATTACK_CLASSES = Array.from(
  { length: 20 },
  (_, index) => `A${index + 1}`,
) as readonly string[];
export const CORPUS_INVARIANTS = Array.from(
  { length: 21 },
  (_, index) => `INV-${String(index + 1).padStart(2, "0")}`,
) as readonly string[];
export const CORPUS_SURFACES = [
  "dom",
  "hidden-dom",
  "aria",
  "metadata",
  "attributes",
  "comments",
  "encoding",
  "unicode",
  "cross-origin",
  "navigation",
  "network",
  "network-mutation",
  "fetch",
  "redirect",
  "form",
  "popup",
  "websocket",
  "beacon",
  "service-worker",
  "webmcp",
  "memory",
  "exfiltration",
  "upload",
  "download",
  "message",
  "paste",
  "guard-provider",
  "semantic-guard",
  "screenshot",
  "file",
] as const;
export const CORPUS_INITIATORS = [
  "none",
  "agent",
  "page-script",
  "form",
  "redirect",
  "webmcp",
  "service-worker",
  "unknown",
] as const;

export type CorpusMode = "attack" | "benign";
export type CorpusKind = "static" | "mutation" | "adaptive-ready";
export type CorpusSurface = (typeof CORPUS_SURFACES)[number];
export type CorpusInitiator = (typeof CORPUS_INITIATORS)[number];
export type CorpusJson = string | number | boolean | null | CorpusJson[] | CorpusJsonObject;
export interface CorpusJsonObject {
  readonly [key: string]: CorpusJson;
}

export interface CorpusPage {
  readonly url: string;
  readonly origin?: string;
}

export interface CorpusStep {
  readonly description: string;
  readonly action?: string;
  readonly target?: string;
}

/** Inert state-mutation metadata; it never carries task/policy/capability/expected fields. */
export interface CorpusMutationMetadata {
  readonly trigger: "load" | "timer" | "action" | "navigation" | "request";
  readonly target?: string;
  readonly delayMs?: number;
  readonly sequence?: readonly string[];
}

/** P1 generator input only; static expected outcomes remain authoritative. */
export interface CorpusAdaptiveMetadata {
  readonly seed: string;
  readonly transformations: readonly string[];
  readonly maxVariants: number;
}

export interface CorpusExpected {
  readonly outcome: "ALLOW" | "ALLOW_SANITIZED" | "WARN" | "RESTRICT" | "BLOCK" | "QUARANTINE";
  readonly reasons?: readonly string[];
  readonly findings?: readonly string[];
  readonly risk?: "NORMAL" | "RESTRICTED" | "READ_ONLY" | "QUARANTINED";
  readonly control?:
    "deterministic" | "semantic-evidence-only" | "approval" | "observed-only" | "unavailable";
}

export interface CorpusCase {
  readonly id: string;
  readonly mode: CorpusMode;
  readonly attackClasses: readonly string[];
  readonly invariants: readonly string[];
  readonly kind: CorpusKind;
  readonly surfaces: readonly CorpusSurface[];
  readonly initiator: CorpusInitiator;
  readonly pages: readonly CorpusPage[];
  readonly task: string;
  readonly taskContract?: Readonly<CorpusJsonObject>;
  readonly policy?: Readonly<CorpusJsonObject>;
  readonly steps?: readonly CorpusStep[];
  readonly mutation?: CorpusMutationMetadata;
  readonly adaptive?: CorpusAdaptiveMetadata;
  readonly expected: CorpusExpected;
  readonly locale?: string;
  readonly tags?: readonly string[];
}

export interface LoadedCorpus {
  readonly schemaVersion: typeof CORPUS_SCHEMA_VERSION;
  readonly cases: readonly CorpusCase[];
  readonly hash: string;
  readonly fixtureHashes: Readonly<Record<string, string>>;
}

export interface CorpusRunResult<Result> {
  readonly id: string;
  readonly result: Result;
}

const DOCUMENT_KEYS = new Set(["schemaVersion", "cases"]);
const CASE_KEYS = new Set([
  "id",
  "mode",
  "attackClasses",
  "invariants",
  "kind",
  "surfaces",
  "initiator",
  "pages",
  "task",
  "taskContract",
  "policy",
  "steps",
  "mutation",
  "adaptive",
  "expected",
  "locale",
  "tags",
]);
const PAGE_KEYS = new Set(["url", "origin"]);
const STEP_KEYS = new Set(["description", "action", "target"]);
const MUTATION_KEYS = new Set(["trigger", "target", "delayMs", "sequence"]);
const ADAPTIVE_KEYS = new Set(["seed", "transformations", "maxVariants"]);
const EXPECTED_KEYS = new Set(["outcome", "reasons", "findings", "risk", "control"]);
const EXPECTED_OUTCOMES = new Set([
  "ALLOW",
  "ALLOW_SANITIZED",
  "WARN",
  "RESTRICT",
  "BLOCK",
  "QUARANTINE",
]);
const RISK_STATES = new Set(["NORMAL", "RESTRICTED", "READ_ONLY", "QUARANTINED"]);
const EXPECTED_CONTROLS = new Set([
  "deterministic",
  "semantic-evidence-only",
  "approval",
  "observed-only",
  "unavailable",
]);
const DANGEROUS_KEY = /^(?:__proto__|prototype|constructor)$/u;
const EXECUTABLE_KEY = /^(?:exec|generator|code|script|require|module|import)$/iu;

/** Strict, bounded validation of a single corpus case. Never invokes accessors. */
export function validateCorpusCase(input: unknown): CorpusCase | null {
  const record = dataRecord(input, CASE_KEYS);
  if (record === null) return null;
  const id = boundedString(record["id"], 1, 128);
  if (id === null || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id)) return null;
  const mode = record["mode"];
  const kind = record["kind"];
  if ((mode !== "attack" && mode !== "benign") || !isCorpusKind(kind)) return null;

  const attackClasses = stringArray(record["attackClasses"], 20, CORPUS_ATTACK_CLASSES);
  const invariants = stringArray(record["invariants"], 21, CORPUS_INVARIANTS, 1);
  const surfaces = stringArray(record["surfaces"], 32, CORPUS_SURFACES, 1) as
    readonly CorpusSurface[] | null;
  const initiator = record["initiator"];
  if (
    attackClasses === null ||
    invariants === null ||
    surfaces === null ||
    !CORPUS_INITIATORS.includes(initiator as CorpusInitiator) ||
    (mode === "attack" && attackClasses.length === 0) ||
    (mode === "benign" && attackClasses.length !== 0)
  ) {
    return null;
  }

  const pages = validatePages(record["pages"]);
  const task = boundedString(record["task"], 1, CORPUS_LIMITS.maxTaskBytes);
  const expected = validateExpected(record["expected"]);
  if (pages === null || task === null || expected === null) return null;

  const taskContract = optionalJsonObject(record["taskContract"]);
  const policy = optionalJsonObject(record["policy"]);
  const steps = validateSteps(record["steps"]);
  const mutation = validateMutation(record["mutation"]);
  const adaptive = validateAdaptive(record["adaptive"]);
  const locale = optionalBoundedString(record["locale"], 64);
  const tags = optionalStringArray(record["tags"], 32);
  if (
    taskContract === false ||
    policy === false ||
    steps === false ||
    mutation === false ||
    adaptive === false ||
    locale === false ||
    tags === false ||
    (kind === "mutation") !== (mutation !== undefined) ||
    (kind === "adaptive-ready") !== (adaptive !== undefined)
  ) {
    return null;
  }

  return Object.freeze({
    id,
    mode,
    attackClasses,
    invariants,
    kind,
    surfaces,
    initiator: initiator as CorpusInitiator,
    pages,
    task,
    ...(taskContract === undefined ? {} : { taskContract }),
    ...(policy === undefined ? {} : { policy }),
    ...(steps === undefined ? {} : { steps }),
    ...(mutation === undefined ? {} : { mutation }),
    ...(adaptive === undefined ? {} : { adaptive }),
    expected,
    ...(locale === undefined ? {} : { locale }),
    ...(tags === undefined ? {} : { tags }),
  });
}

/** Canonical corpus hash: schema + cases sorted by ID + fixture hashes sorted by path. */
export function corpusHash(
  cases: readonly CorpusCase[],
  fixtureHashes: Readonly<Record<string, string>> = {},
): string {
  const sortedCases = [...cases].sort((left, right) => left.id.localeCompare(right.id));
  const sortedFixtures = Object.entries(fixtureHashes)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([path, digest]) => ({ path, digest }));
  return hash(
    stableSerialize({
      schemaVersion: CORPUS_SCHEMA_VERSION,
      cases: sortedCases,
      fixtures: sortedFixtures,
    }),
  );
}

/** Bounded loader for a corpus JSON document without filesystem fixture resolution. */
export function loadCorpusDocument(text: string): LoadedCorpus {
  if (Buffer.byteLength(text, "utf8") > CORPUS_LIMITS.maxFileBytes) {
    throw new TypeError("corpus file exceeds the size limit");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError("corpus file is not valid JSON");
  }
  const document = dataRecord(parsed, DOCUMENT_KEYS);
  if (document === null || document["schemaVersion"] !== CORPUS_SCHEMA_VERSION) {
    throw new TypeError("corpus document must declare the current closed schemaVersion");
  }
  const rawCases = document["cases"];
  if (
    !Array.isArray(rawCases) ||
    rawCases.length === 0 ||
    rawCases.length > CORPUS_LIMITS.maxCases
  ) {
    throw new TypeError("corpus document must have a nonempty bounded cases array");
  }
  const cases: CorpusCase[] = [];
  const ids = new Set<string>();
  for (const raw of rawCases) {
    const validated = validateCorpusCase(raw);
    if (validated === null || ids.has(validated.id)) {
      throw new TypeError("corpus document contains an invalid or duplicate case");
    }
    ids.add(validated.id);
    cases.push(validated);
  }
  const frozenCases = Object.freeze(cases.sort((left, right) => left.id.localeCompare(right.id)));
  return Object.freeze({
    schemaVersion: CORPUS_SCHEMA_VERSION,
    cases: frozenCases,
    hash: corpusHash(frozenCases),
    fixtureHashes: Object.freeze({}),
  });
}

/** Load a corpus manifest and include every referenced local fixture in its stable hash. */
export function loadCorpusFile(path: string): LoadedCorpus {
  const manifestPath = realpathSync(path);
  const root = dirname(manifestPath);
  const loaded = loadCorpusDocument(readFileSync(manifestPath, "utf8"));
  const fixtureHashes: Record<string, string> = {};
  for (const item of loaded.cases) {
    for (const page of item.pages) {
      const fixturePath = page.url.split(/[?#]/u, 1)[0];
      if (fixturePath === undefined || !/\.(?:html|json|txt)$/u.test(fixturePath)) continue;
      const relative = fixturePath.replace(/^\/+/, "");
      const candidate = realpathSync(resolve(root, relative));
      if (candidate !== root && !candidate.startsWith(`${root}${sep}`)) {
        throw new TypeError("corpus fixture escapes its root");
      }
      const stats = statSync(candidate);
      if (!stats.isFile() || stats.size > CORPUS_LIMITS.maxFixtureBytes) {
        throw new TypeError("corpus fixture is missing or oversized");
      }
      fixtureHashes[`/${relative.replaceAll("\\", "/")}`] = createHash("sha256")
        .update(readFileSync(candidate))
        .digest("hex");
    }
  }
  const frozenFixtures = Object.freeze(
    Object.fromEntries(Object.entries(fixtureHashes).sort(([a], [b]) => a.localeCompare(b))),
  );
  return Object.freeze({
    ...loaded,
    hash: corpusHash(loaded.cases, frozenFixtures),
    fixtureHashes: frozenFixtures,
  });
}

/** Deterministic tuples suitable for `it.each(corpusVitestCases(corpus))`. */
export function corpusVitestCases(
  corpus: LoadedCorpus,
  predicate: (item: CorpusCase) => boolean = () => true,
): readonly (readonly [name: string, item: CorpusCase])[] {
  return Object.freeze(
    corpus.cases.filter(predicate).map((item) => Object.freeze([item.id, item] as const)),
  );
}

/** Framework-neutral sequential runner seam used by Vitest and the later CLI runner. */
export async function runCorpusCases<Result>(
  corpus: LoadedCorpus,
  run: (item: CorpusCase) => Promise<Result> | Result,
): Promise<readonly CorpusRunResult<Result>[]> {
  const results: CorpusRunResult<Result>[] = [];
  for (const item of corpus.cases) {
    results.push(Object.freeze({ id: item.id, result: await run(item) }));
  }
  return Object.freeze(results);
}

function validatePages(value: unknown): readonly CorpusPage[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > CORPUS_LIMITS.maxPages) {
    return null;
  }
  const pages: CorpusPage[] = [];
  for (const item of value) {
    const page = dataRecord(item, PAGE_KEYS);
    if (page === null) return null;
    const url = boundedString(page["url"], 1, 2_048);
    const origin = optionalBoundedString(page["origin"], 64);
    if (
      url === null ||
      !url.startsWith("/") ||
      url.includes("\\") ||
      url.includes("\0") ||
      origin === false ||
      (origin !== undefined && !/^[a-z][a-z0-9-]{0,31}$/.test(origin))
    ) {
      return null;
    }
    pages.push(Object.freeze({ url, ...(origin === undefined ? {} : { origin }) }));
  }
  return Object.freeze(pages);
}

function validateExpected(value: unknown): CorpusExpected | null {
  const expected = dataRecord(value, EXPECTED_KEYS);
  if (expected === null || !EXPECTED_OUTCOMES.has(expected["outcome"] as string)) return null;
  const reasons = optionalStringArray(expected["reasons"], 64);
  const findings = optionalStringArray(expected["findings"], 64);
  const risk = expected["risk"];
  const control = expected["control"];
  if (
    reasons === false ||
    findings === false ||
    (risk !== undefined && !RISK_STATES.has(risk as string)) ||
    (control !== undefined && !EXPECTED_CONTROLS.has(control as string))
  ) {
    return null;
  }
  return Object.freeze({
    outcome: expected["outcome"] as CorpusExpected["outcome"],
    ...(reasons === undefined ? {} : { reasons }),
    ...(findings === undefined ? {} : { findings }),
    ...(risk === undefined ? {} : { risk: risk as Exclude<CorpusExpected["risk"], undefined> }),
    ...(control === undefined
      ? {}
      : { control: control as Exclude<CorpusExpected["control"], undefined> }),
  });
}

function validateSteps(value: unknown): readonly CorpusStep[] | undefined | false {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > CORPUS_LIMITS.maxSteps) return false;
  const steps: CorpusStep[] = [];
  for (const item of value) {
    const step = dataRecord(item, STEP_KEYS);
    if (step === null) return false;
    const description = boundedString(step["description"], 1, 1_024);
    const action = optionalBoundedString(step["action"], 128);
    const target = optionalBoundedString(step["target"], 2_048);
    if (description === null || action === false || target === false) return false;
    steps.push(
      Object.freeze({
        description,
        ...(action === undefined ? {} : { action }),
        ...(target === undefined ? {} : { target }),
      }),
    );
  }
  return Object.freeze(steps);
}

function validateMutation(value: unknown): CorpusMutationMetadata | undefined | false {
  if (value === undefined) return undefined;
  const record = dataRecord(value, MUTATION_KEYS);
  if (record === null) return false;
  const trigger = record["trigger"];
  const target = optionalBoundedString(record["target"], 2_048);
  const delayMs = record["delayMs"];
  const sequence = optionalStringArray(record["sequence"], 32);
  if (
    !["load", "timer", "action", "navigation", "request"].includes(trigger as string) ||
    target === false ||
    sequence === false ||
    (delayMs !== undefined &&
      (typeof delayMs !== "number" ||
        !Number.isInteger(delayMs) ||
        delayMs < 0 ||
        delayMs > 10_000))
  ) {
    return false;
  }
  return Object.freeze({
    trigger: trigger as CorpusMutationMetadata["trigger"],
    ...(target === undefined ? {} : { target }),
    ...(delayMs === undefined ? {} : { delayMs }),
    ...(sequence === undefined ? {} : { sequence }),
  });
}

function validateAdaptive(value: unknown): CorpusAdaptiveMetadata | undefined | false {
  if (value === undefined) return undefined;
  const record = dataRecord(value, ADAPTIVE_KEYS);
  if (record === null) return false;
  const seed = boundedString(record["seed"], 1, 256);
  const transformations = stringArray(record["transformations"], 32, undefined, 1);
  const maxVariants = record["maxVariants"];
  if (
    seed === null ||
    transformations === null ||
    typeof maxVariants !== "number" ||
    !Number.isInteger(maxVariants) ||
    maxVariants < 1 ||
    maxVariants > 1_000
  ) {
    return false;
  }
  return Object.freeze({ seed, transformations, maxVariants });
}

function optionalJsonObject(value: unknown): Readonly<CorpusJsonObject> | undefined | false {
  if (value === undefined) return undefined;
  const cloned = cloneJson(value, 0);
  return cloned !== null && !Array.isArray(cloned) && typeof cloned === "object"
    ? Object.freeze(cloned)
    : false;
}

function cloneJson(value: unknown, depth: number): CorpusJson | null {
  if (depth > CORPUS_LIMITS.maxDepth) return null;
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") return boundedString(value, 0, CORPUS_LIMITS.maxStringBytes);
  if (Array.isArray(value)) {
    if (value.length > CORPUS_LIMITS.maxArrayItems) return null;
    const output: CorpusJson[] = [];
    for (const item of value) {
      const cloned = cloneJson(item, depth + 1);
      if (cloned === null && item !== null) return null;
      output.push(cloned);
    }
    return Object.freeze(output) as CorpusJson[];
  }
  const record = dataRecord(value);
  if (record === null || Object.keys(record).length > CORPUS_LIMITS.maxArrayItems) return null;
  const output: Record<string, CorpusJson> = Object.create(null) as Record<string, CorpusJson>;
  for (const [key, item] of Object.entries(record)) {
    if (EXECUTABLE_KEY.test(key) || Buffer.byteLength(key, "utf8") > 128) return null;
    const cloned = cloneJson(item, depth + 1);
    if (cloned === null && item !== null) return null;
    output[key] = cloned;
  }
  return Object.freeze(output);
}

function stringArray(
  value: unknown,
  maxItems: number,
  allowed?: readonly string[],
  minItems = 0,
): readonly string[] | null {
  if (!Array.isArray(value) || value.length < minItems || value.length > maxItems) return null;
  const strings: string[] = [];
  for (const item of value) {
    const string = boundedString(item, 1, 128);
    if (
      string === null ||
      (allowed !== undefined && !allowed.includes(string)) ||
      strings.includes(string)
    ) {
      return null;
    }
    strings.push(string);
  }
  return Object.freeze(strings);
}

function optionalStringArray(
  value: unknown,
  maxItems: number,
): readonly string[] | undefined | false {
  if (value === undefined) return undefined;
  return stringArray(value, maxItems) ?? false;
}

function boundedString(value: unknown, minBytes: number, maxBytes: number): string | null {
  if (typeof value !== "string") return null;
  const bytes = Buffer.byteLength(value, "utf8");
  return bytes >= minBytes && bytes <= maxBytes ? value : null;
}

function optionalBoundedString(value: unknown, maxBytes: number): string | undefined | false {
  if (value === undefined) return undefined;
  return boundedString(value, 1, maxBytes) ?? false;
}

function isCorpusKind(value: unknown): value is CorpusKind {
  return value === "static" || value === "mutation" || value === "adaptive-ready";
}

function dataRecord(
  input: unknown,
  allowedKeys?: ReadonlySet<string>,
): Record<string, unknown> | null {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return null;
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Object.keys(descriptors);
  if (
    (allowedKeys !== undefined && keys.some((key) => !allowedKeys.has(key))) ||
    keys.some(
      (key) =>
        descriptors[key]?.get !== undefined ||
        descriptors[key]?.set !== undefined ||
        DANGEROUS_KEY.test(key),
    )
  ) {
    return null;
  }
  const output: Record<string, unknown> = {};
  for (const key of keys) output[key] = descriptors[key]?.value;
  return output;
}
