import type {
  BoundingBox,
  ProbeLink,
  ProbeMetadata,
  ProbeNode,
  ProbeResult,
  ProbeTruncation,
} from "./probe-result.js";

/**
 * Runtime validation of the in-page probe output (TB2). Probe output is
 * untrusted data returned from a page; adapters must validate it with
 * `validateProbeResult` before it enters the observation pipeline. Hand-rolled
 * to keep `core` dependency-free, mirroring `validateFinding`/`validateScanResult`.
 */
const BOX_KEYS = new Set(["x", "y", "width", "height"]);
const TRUNCATION_KEYS = new Set(["nodes", "textBytes", "comments", "metadata", "links", "time"]);
const METADATA_KEYS = new Set(["title", "meta", "jsonLd", "noscript"]);
const LINK_KEYS = new Set(["text", "href"]);
const NODE_KEYS = new Set([
  "selector",
  "tagName",
  "text",
  "display",
  "visibility",
  "opacity",
  "ariaHidden",
  "hidden",
  "role",
  "ariaLabel",
  "ariaDescription",
  "attributes",
  "dimensions",
  "boundingBox",
  "frameOrigin",
  "fontSize",
  "color",
  "backgroundColor",
  "position",
  "transform",
  "clipPath",
  "overflow",
  "inViewport",
  "pseudoBefore",
  "pseudoAfter",
]);
const RESULT_KEYS = new Set([
  "probeVersion",
  "truncated",
  "truncation",
  "nodes",
  "comments",
  "metadata",
  "links",
]);

const NULLABLE_STRING_NODE_KEYS = [
  "role",
  "ariaLabel",
  "ariaDescription",
  "fontSize",
  "color",
  "backgroundColor",
  "position",
  "transform",
  "clipPath",
  "overflow",
  "pseudoBefore",
  "pseudoAfter",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      return false;
    }
  }
  return true;
}

function validateBox(value: unknown): BoundingBox | null {
  if (!isRecord(value) || !hasOnlyKeys(value, BOX_KEYS)) {
    return null;
  }
  const { x, y, width, height } = value;
  if (
    typeof x !== "number" ||
    typeof y !== "number" ||
    typeof width !== "number" ||
    typeof height !== "number"
  ) {
    return null;
  }
  return { x, y, width, height };
}

function validateTruncation(value: unknown): ProbeTruncation | null {
  if (!isRecord(value) || !hasOnlyKeys(value, TRUNCATION_KEYS)) {
    return null;
  }
  for (const key of TRUNCATION_KEYS) {
    if (typeof value[key] !== "boolean") {
      return null;
    }
  }
  return {
    nodes: value["nodes"] as boolean,
    textBytes: value["textBytes"] as boolean,
    comments: value["comments"] as boolean,
    metadata: value["metadata"] as boolean,
    links: value["links"] as boolean,
    time: value["time"] as boolean,
  };
}

function validateStringMap(value: unknown): Readonly<Record<string, string>> | null {
  if (!isRecord(value)) {
    return null;
  }
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== "string") {
      return null;
    }
    out[key] = item;
  }
  return out;
}

function validateNode(value: unknown): ProbeNode | null {
  if (!isRecord(value) || !hasOnlyKeys(value, NODE_KEYS)) {
    return null;
  }
  for (const key of ["selector", "tagName", "text", "display", "visibility", "frameOrigin"]) {
    if (typeof value[key] !== "string") {
      return null;
    }
  }
  for (const key of NULLABLE_STRING_NODE_KEYS) {
    if (value[key] !== null && typeof value[key] !== "string") {
      return null;
    }
  }
  if (typeof value["opacity"] !== "number") {
    return null;
  }
  if (typeof value["ariaHidden"] !== "boolean" || typeof value["hidden"] !== "boolean") {
    return null;
  }
  if (typeof value["inViewport"] !== "boolean") {
    return null;
  }
  const attributes = validateStringMap(value["attributes"]);
  if (attributes === null) {
    return null;
  }
  const dimensions = value["dimensions"];
  const boundingBox = value["boundingBox"];
  const validatedDimensions = dimensions === null ? null : validateBox(dimensions);
  const validatedBox = boundingBox === null ? null : validateBox(boundingBox);
  if (
    (dimensions !== null && validatedDimensions === null) ||
    (boundingBox !== null && validatedBox === null)
  ) {
    return null;
  }
  return {
    selector: value["selector"] as string,
    tagName: value["tagName"] as string,
    text: value["text"] as string,
    display: value["display"] as string,
    visibility: value["visibility"] as string,
    opacity: value["opacity"],
    ariaHidden: value["ariaHidden"],
    hidden: value["hidden"],
    role: value["role"] as string | null,
    ariaLabel: value["ariaLabel"] as string | null,
    ariaDescription: value["ariaDescription"] as string | null,
    attributes,
    dimensions: validatedDimensions,
    boundingBox: validatedBox,
    frameOrigin: value["frameOrigin"] as string,
    fontSize: value["fontSize"] as string | null,
    color: value["color"] as string | null,
    backgroundColor: value["backgroundColor"] as string | null,
    position: value["position"] as string | null,
    transform: value["transform"] as string | null,
    clipPath: value["clipPath"] as string | null,
    overflow: value["overflow"] as string | null,
    inViewport: value["inViewport"],
    pseudoBefore: value["pseudoBefore"] as string | null,
    pseudoAfter: value["pseudoAfter"] as string | null,
  };
}

function validateMetadata(value: unknown): ProbeMetadata | null {
  if (!isRecord(value) || !hasOnlyKeys(value, METADATA_KEYS)) {
    return null;
  }
  if (typeof value["title"] !== "string") {
    return null;
  }
  const meta = validateStringMap(value["meta"]);
  if (meta === null) {
    return null;
  }
  const jsonLd = value["jsonLd"];
  const noscript = value["noscript"];
  if (!isStringArray(jsonLd)) {
    return null;
  }
  if (!isStringArray(noscript)) {
    return null;
  }
  return {
    title: value["title"],
    meta,
    jsonLd,
    noscript,
  };
}

function validateLink(value: unknown): ProbeLink | null {
  if (!isRecord(value) || !hasOnlyKeys(value, LINK_KEYS)) {
    return null;
  }
  if (typeof value["text"] !== "string" || typeof value["href"] !== "string") {
    return null;
  }
  return { text: value["text"], href: value["href"] };
}

/** Validate probe output; returns the typed result or `null` when malformed. */
export function validateProbeResult(input: unknown): ProbeResult | null {
  if (!isRecord(input) || !hasOnlyKeys(input, RESULT_KEYS)) {
    return null;
  }
  if (typeof input["probeVersion"] !== "number" || !Number.isInteger(input["probeVersion"])) {
    return null;
  }
  if (typeof input["truncated"] !== "boolean") {
    return null;
  }
  const truncation = validateTruncation(input["truncation"]);
  if (truncation === null) {
    return null;
  }
  if (!Array.isArray(input["nodes"])) {
    return null;
  }
  const nodes: ProbeNode[] = [];
  for (const item of input["nodes"]) {
    const node = validateNode(item);
    if (node === null) {
      return null;
    }
    nodes.push(node);
  }
  if (!isStringArray(input["comments"])) {
    return null;
  }
  const metadata = validateMetadata(input["metadata"]);
  if (metadata === null) {
    return null;
  }
  if (!Array.isArray(input["links"])) {
    return null;
  }
  const links: ProbeLink[] = [];
  for (const item of input["links"]) {
    const link = validateLink(item);
    if (link === null) {
      return null;
    }
    links.push(link);
  }
  return {
    probeVersion: input["probeVersion"],
    truncated: input["truncated"],
    truncation,
    nodes,
    comments: input["comments"],
    metadata,
    links,
  };
}
