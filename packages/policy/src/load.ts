import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import { isReasonCode, isValidInternalNetworkRange } from "@openagentfence/core";
import { isAlias, isMap, isScalar, isSeq, parseDocument } from "yaml";
import {
  brandPolicyDocument,
  type PolicyDocument,
  type ValidatedPolicyDocument,
} from "./document.js";

const MAX_BYTES = 1024 * 1024;
const MAX_DEPTH = 16;
const MAX_NODES = 1_000;
const MAX_ERRORS = 20;
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const ACTION_KEYS = new Set([
  "upload",
  "delete",
  "purchase",
  "message",
  "execute_script",
  "download",
  "authenticate",
  "publish",
  "change_setting",
]);

/** A safe, bounded validation failure. It never includes policy source text. @public */
export class PolicyDocumentError extends Error {
  /** Stable machine-readable category for callers and the future CLI. */
  public readonly code: "POLICY_DOCUMENT_INVALID" | "POLICY_DOCUMENT_TOO_LARGE";
  /** At most twenty path-qualified validation errors. */
  public readonly errors: readonly string[];

  public constructor(
    code: "POLICY_DOCUMENT_INVALID" | "POLICY_DOCUMENT_TOO_LARGE",
    errors: readonly string[],
  ) {
    super(errors[0] ?? "policy document is invalid");
    this.name = "PolicyDocumentError";
    this.code = code;
    this.errors = errors.slice(0, MAX_ERRORS);
  }
}

/**
 * Loads either a file path containing YAML/JSON or a programmatically supplied
 * document. Strings are always paths, never source text, eliminating source /
 * path ambiguity at TB1.
 *
 * @public
 */
export async function loadPolicyDocument(
  input: string | PolicyDocument,
): Promise<ValidatedPolicyDocument> {
  if (typeof input !== "string") {
    return validateAndBrand(input, "policy");
  }

  let source: string;
  try {
    source = await readFile(input, "utf8");
  } catch {
    throw invalid(["policy: could not read policy file"]);
  }
  return parsePolicySource(source, input, extname(input).toLowerCase());
}

/** Parses bounded policy source for callers that already own the bytes. @public */
export function parsePolicyDocumentSource(
  source: string,
  sourceName = "policy",
): ValidatedPolicyDocument {
  return parsePolicySource(source, sourceName, extname(sourceName).toLowerCase());
}

function parsePolicySource(
  source: string,
  sourceName: string,
  extension: string,
): ValidatedPolicyDocument {
  if (Buffer.byteLength(source, "utf8") > MAX_BYTES) {
    throw new PolicyDocumentError("POLICY_DOCUMENT_TOO_LARGE", [
      `${sourceName}: exceeds 1048576 bytes`,
    ]);
  }

  if (extension === ".json") {
    try {
      return validateAndBrand(JSON.parse(source) as unknown, sourceName);
    } catch (error: unknown) {
      if (error instanceof PolicyDocumentError) {
        throw error;
      }
      throw invalid([`${sourceName}: invalid JSON`]);
    }
  }

  if (/^\s*%/m.test(source)) {
    throw invalid([`${sourceName}: YAML directives are not allowed`]);
  }
  const document = parseDocument(source, {
    version: "1.2",
    schema: "core",
    strict: true,
    stringKeys: true,
    uniqueKeys: true,
    customTags: [],
    merge: false,
    resolveKnownTags: false,
    prettyErrors: false,
  });
  if (document.errors.length > 0 || document.warnings.length > 0) {
    throw invalid([`${sourceName}: invalid YAML`]);
  }
  const yamlErrors: string[] = [];
  inspectYamlNode(document.contents, sourceName, 0, { count: 0 }, yamlErrors);
  if (yamlErrors.length > 0) {
    throw invalid(yamlErrors);
  }
  try {
    return validateAndBrand(document.toJS({ maxAliasCount: 0 }), sourceName);
  } catch (error: unknown) {
    if (error instanceof PolicyDocumentError) {
      throw error;
    }
    throw invalid([`${sourceName}: invalid YAML`]);
  }
}

function inspectYamlNode(
  node: unknown,
  path: string,
  depth: number,
  state: { count: number },
  errors: string[],
): void {
  state.count += 1;
  if (state.count > MAX_NODES) {
    errors.push(`${path}: exceeds ${MAX_NODES} YAML nodes`);
    return;
  }
  if (depth > MAX_DEPTH) {
    errors.push(`${path}: exceeds YAML nesting depth ${MAX_DEPTH}`);
    return;
  }
  if (isAlias(node)) {
    errors.push(`${path}: YAML aliases are not allowed`);
    return;
  }
  if (node !== null && typeof node === "object" && "anchor" in node && node.anchor !== undefined) {
    errors.push(`${path}: YAML anchors are not allowed`);
    return;
  }
  if (node !== null && typeof node === "object" && "tag" in node && node.tag !== undefined) {
    errors.push(`${path}: explicit YAML tags are not allowed`);
    return;
  }
  if (isMap(node)) {
    for (const pair of node.items) {
      inspectYamlNode(pair.key, path, depth + 1, state, errors);
      inspectYamlNode(pair.value, path, depth + 1, state, errors);
    }
  } else if (isSeq(node)) {
    for (const item of node.items) {
      inspectYamlNode(item, path, depth + 1, state, errors);
    }
  } else if (isScalar(node) && typeof node.value === "string" && node.value.length > MAX_BYTES) {
    errors.push(`${path}: scalar exceeds byte limit`);
  }
}

function validateAndBrand(input: unknown, path: string): ValidatedPolicyDocument {
  const errors: string[] = [];
  const value = validateDocument(input, path, 0, { count: 0 }, errors);
  if (errors.length > 0 || value === undefined) {
    throw invalid(errors.length > 0 ? errors : [`${path}: invalid policy document`]);
  }
  return brandPolicyDocument(value);
}

function validateDocument(
  input: unknown,
  path: string,
  depth: number,
  state: { count: number },
  errors: string[],
): PolicyDocument | undefined {
  const record = recordAt(input, path, depth, state, errors);
  if (record === undefined) return undefined;
  rejectUnknown(
    record,
    [
      "version",
      "defaults",
      "navigation",
      "actions",
      "secrets",
      "injection",
      "budgets",
      "scanners",
      "suppressions",
      "risk",
    ],
    path,
    errors,
  );
  if (record["version"] !== 1) errors.push(`${path}.version: must equal 1`);

  const defaults = objectSection(record, "defaults", path, depth, state, errors, [
    "unknown_action",
    "scanner_failure",
  ]);
  const navigation = objectSection(record, "navigation", path, depth, state, errors, [
    "mode",
    "block_private_networks",
    "max_redirect_hops",
    "internal_network_ranges",
  ]);
  const actions = objectSection(record, "actions", path, depth, state, errors, undefined);
  const secrets = objectSection(record, "secrets", path, depth, state, errors, ["resolution"]);
  const injection = objectSection(record, "injection", path, depth, state, errors, [
    "high_confidence",
    "critical",
  ]);
  const budgets = objectSection(record, "budgets", path, depth, state, errors, [
    "max_actions",
    "max_duration_ms",
    "max_navigations",
    "on_exceeded",
  ]);
  const scanners = objectSection(record, "scanners", path, depth, state, errors, undefined);
  const risk = objectSection(record, "risk", path, depth, state, errors, [
    "restricted_at",
    "quarantine_at",
  ]);

  if (defaults !== undefined) {
    if (defaults["unknown_action"] !== undefined && defaults["unknown_action"] !== "block")
      errors.push(`${path}.defaults.unknown_action: must be block`);
    const scannerFailure = objectSection(
      defaults,
      "scanner_failure",
      `${path}.defaults`,
      depth + 1,
      state,
      errors,
      ["low_risk", "high_risk"],
    );
    if (scannerFailure !== undefined) {
      if (
        scannerFailure["low_risk"] !== undefined &&
        scannerFailure["low_risk"] !== "warn" &&
        scannerFailure["low_risk"] !== "block"
      )
        errors.push(`${path}.defaults.scanner_failure.low_risk: must be warn or block`);
      if (scannerFailure["high_risk"] !== undefined && scannerFailure["high_risk"] !== "block")
        errors.push(`${path}.defaults.scanner_failure.high_risk: must be block`);
    }
  }
  if (navigation !== undefined) {
    const mode = navigation["mode"];
    if (
      mode !== undefined &&
      mode !== "same-site" &&
      mode !== "same-origin" &&
      mode !== "allowlist" &&
      mode !== "none"
    )
      errors.push(`${path}.navigation.mode: invalid mode`);
    if (
      navigation["block_private_networks"] !== undefined &&
      typeof navigation["block_private_networks"] !== "boolean"
    )
      errors.push(`${path}.navigation.block_private_networks: must be boolean`);
    const maxRedirectHops = navigation["max_redirect_hops"];
    if (
      maxRedirectHops !== undefined &&
      (typeof maxRedirectHops !== "number" ||
        !Number.isInteger(maxRedirectHops) ||
        maxRedirectHops < 0 ||
        maxRedirectHops > 5)
    )
      errors.push(`${path}.navigation.max_redirect_hops: must be an integer from 0 to 5`);
    const internalRanges = navigation["internal_network_ranges"];
    if (
      internalRanges !== undefined &&
      (!Array.isArray(internalRanges) ||
        internalRanges.length > 64 ||
        internalRanges.some(
          (range) => typeof range !== "string" || !isValidInternalNetworkRange(range),
        ))
    )
      errors.push(`${path}.navigation.internal_network_ranges: must be at most 64 CIDR ranges`);
  }
  if (actions !== undefined) {
    for (const [key, action] of Object.entries(actions)) {
      if (!ACTION_KEYS.has(key)) errors.push(`${path}.actions.${key}: unknown action`);
      if (action !== "deny" && action !== "approval" && action !== "allow")
        errors.push(`${path}.actions.${key}: must be deny, approval, or allow`);
    }
  }
  if (
    secrets !== undefined &&
    secrets["resolution"] !== undefined &&
    secrets["resolution"] !== "executor_only"
  )
    errors.push(`${path}.secrets.resolution: must be executor_only`);
  if (injection !== undefined) {
    if (
      injection["high_confidence"] !== undefined &&
      injection["high_confidence"] !== "restricted_mode" &&
      injection["high_confidence"] !== "block"
    )
      errors.push(`${path}.injection.high_confidence: invalid value`);
    if (
      injection["critical"] !== undefined &&
      injection["critical"] !== "quarantine" &&
      injection["critical"] !== "block"
    )
      errors.push(`${path}.injection.critical: invalid value`);
  }
  if (budgets !== undefined) {
    for (const key of ["max_actions", "max_duration_ms", "max_navigations"] as const) {
      const budget = budgets[key];
      if (
        budget !== undefined &&
        (typeof budget !== "number" || !Number.isFinite(budget) || budget < 0)
      )
        errors.push(`${path}.budgets.${key}: must be a non-negative number`);
    }
    if (
      budgets["on_exceeded"] !== undefined &&
      budgets["on_exceeded"] !== "block" &&
      budgets["on_exceeded"] !== "restricted_mode"
    )
      errors.push(`${path}.budgets.on_exceeded: invalid value`);
  }
  if (scanners !== undefined)
    validateScanners(scanners, `${path}.scanners`, depth + 1, state, errors);
  if (risk !== undefined)
    for (const key of ["restricted_at", "quarantine_at"] as const)
      if (
        risk[key] !== undefined &&
        (typeof risk[key] !== "number" || !Number.isFinite(risk[key]) || risk[key] < 0)
      )
        errors.push(`${path}.risk.${key}: must be a non-negative number`);
  validateSuppressions(record["suppressions"], `${path}.suppressions`, depth + 1, state, errors);
  if (errors.length > 0) return undefined;
  return clonePolicy(record) as PolicyDocument;
}

function validateScanners(
  input: Record<string, unknown>,
  path: string,
  depth: number,
  state: { count: number },
  errors: string[],
): void {
  for (const [name, config] of Object.entries(input)) {
    const scanner = recordAt(config, `${path}.${name}`, depth, state, errors);
    if (scanner === undefined) continue;
    rejectUnknown(scanner, ["enabled", "rules"], `${path}.${name}`, errors);
    if (scanner["enabled"] !== undefined && typeof scanner["enabled"] !== "boolean")
      errors.push(`${path}.${name}.enabled: must be boolean`);
    const rules = scanner["rules"];
    if (rules !== undefined) {
      const ruleRecord = recordAt(rules, `${path}.${name}.rules`, depth + 1, state, errors);
      if (ruleRecord !== undefined) {
        for (const [ruleId, rawRule] of Object.entries(ruleRecord)) {
          const rule = recordAt(
            rawRule,
            `${path}.${name}.rules.${ruleId}`,
            depth + 2,
            state,
            errors,
          );
          if (rule === undefined) continue;
          rejectUnknown(
            rule,
            ["threshold", "mode", "origins"],
            `${path}.${name}.rules.${ruleId}`,
            errors,
          );
          validateThreshold(rule, `${path}.${name}.rules.${ruleId}`, errors);
          const origins = rule["origins"];
          if (origins !== undefined) {
            const originRecord = recordAt(
              origins,
              `${path}.${name}.rules.${ruleId}.origins`,
              depth + 3,
              state,
              errors,
            );
            if (originRecord !== undefined)
              for (const [origin, rawOrigin] of Object.entries(originRecord)) {
                const originRule = recordAt(
                  rawOrigin,
                  `${path}.${name}.rules.${ruleId}.origins.${origin}`,
                  depth + 4,
                  state,
                  errors,
                );
                if (originRule !== undefined) {
                  rejectUnknown(
                    originRule,
                    ["threshold", "mode"],
                    `${path}.${name}.rules.${ruleId}.origins.${origin}`,
                    errors,
                  );
                  validateThreshold(
                    originRule,
                    `${path}.${name}.rules.${ruleId}.origins.${origin}`,
                    errors,
                  );
                }
              }
          }
        }
      }
    }
  }

  function validateThreshold(input: Record<string, unknown>, path: string, errors: string[]): void {
    const threshold = input["threshold"];
    if (
      threshold !== undefined &&
      (typeof threshold !== "number" ||
        !Number.isFinite(threshold) ||
        threshold < 0 ||
        threshold > 1)
    )
      errors.push(`${path}.threshold: must be a number from 0 to 1`);
    const mode = input["mode"];
    if (mode !== undefined && mode !== "warn" && mode !== "block")
      errors.push(`${path}.mode: must be warn or block`);
  }
}

function validateSuppressions(
  input: unknown,
  path: string,
  depth: number,
  state: { count: number },
  errors: string[],
): void {
  if (input === undefined) return;
  if (!Array.isArray(input)) {
    errors.push(`${path}: must be an array`);
    return;
  }
  for (let index = 0; index < input.length; index += 1) {
    const item = recordAt(input[index], `${path}[${index}]`, depth, state, errors);
    if (item === undefined) continue;
    rejectUnknown(item, ["rule", "scope", "justification", "expires"], `${path}[${index}]`, errors);
    for (const key of ["rule", "scope", "justification"] as const)
      if (typeof item[key] !== "string" || item[key].length === 0)
        errors.push(`${path}[${index}].${key}: must be a non-empty string`);
    const expires = item["expires"];
    if (expires !== undefined) {
      if (typeof expires !== "string") errors.push(`${path}[${index}].expires: must be a string`);
      else {
        const expiresAt = Date.parse(expires);
        if (Number.isNaN(expiresAt))
          errors.push(`${path}[${index}].expires: must be an ISO-compatible timestamp`);
        else if (expiresAt <= Date.now())
          errors.push(`${path}[${index}].expires: must be a future timestamp`);
      }
    }
    if (typeof item["rule"] === "string" && isReasonCode(item["rule"]))
      errors.push(`${path}[${index}].rule: targets final deterministic control`);
  }
}

function objectSection(
  input: Record<string, unknown>,
  key: string,
  path: string,
  depth: number,
  state: { count: number },
  errors: string[],
  allowed: readonly string[] | undefined,
): Record<string, unknown> | undefined {
  const value = input[key];
  if (value === undefined) return undefined;
  const section = recordAt(value, `${path}.${key}`, depth + 1, state, errors);
  if (section !== undefined && allowed !== undefined)
    rejectUnknown(section, allowed, `${path}.${key}`, errors);
  return section;
}

function recordAt(
  input: unknown,
  path: string,
  depth: number,
  state: { count: number },
  errors: string[],
): Record<string, unknown> | undefined {
  state.count += 1;
  if (state.count > MAX_NODES) {
    errors.push(`${path}: exceeds ${MAX_NODES} nodes`);
    return undefined;
  }
  if (depth > MAX_DEPTH) {
    errors.push(`${path}: exceeds nesting depth ${MAX_DEPTH}`);
    return undefined;
  }
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    errors.push(`${path}: must be an object`);
    return undefined;
  }
  const prototype = Reflect.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    errors.push(`${path}: must be a plain object`);
    return undefined;
  }
  return input as Record<string, unknown>;
}

function rejectUnknown(
  input: Record<string, unknown>,
  allowed: readonly string[] | undefined,
  path: string,
  errors: string[],
): void {
  for (const key of Object.keys(input)) {
    if (UNSAFE_KEYS.has(key)) errors.push(`${path}.${key}: unsafe key`);
    else if (allowed !== undefined && !allowed.includes(key))
      errors.push(`${path}.${key}: unknown key`);
    if (containsEnvironmentSubstitution(input[key]))
      errors.push(`${path}.${key}: environment substitution is not allowed`);
  }
}

function containsEnvironmentSubstitution(input: unknown): boolean {
  return typeof input === "string" && /\$\{[^}]*\}/.test(input);
}

function clonePolicy(input: Record<string, unknown>): unknown {
  if (Array.isArray(input)) return input.map((item) => clonePolicyValue(item));
  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) output[key] = clonePolicyValue(value);
  return output;
}

function clonePolicyValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => clonePolicyValue(item));
  if (value !== null && typeof value === "object")
    return clonePolicy(value as Record<string, unknown>);
  return value;
}

function invalid(errors: readonly string[]): PolicyDocumentError {
  return new PolicyDocumentError("POLICY_DOCUMENT_INVALID", errors);
}
