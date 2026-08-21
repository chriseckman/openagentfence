import type { ProbeLink, ProbeMetadata, ProbeNode, ProbeResult } from "@openagentfence/core";

export const VISIBILITY_CLASSES = [
  "VISIBLE",
  "VISIBLE_LOW_CONFIDENCE",
  "ACCESSIBILITY_ONLY",
  "HIDDEN",
  "OFFSCREEN",
  "ZERO_SIZE",
  "CSS_GENERATED",
  "METADATA",
  "SCRIPT_OR_CODE",
  "EMBEDDED_FRAME",
  "UNKNOWN",
] as const;

export type VisibilityClass = (typeof VISIBILITY_CLASSES)[number];

export interface ClassifiedNode {
  readonly node: ProbeNode;
  readonly visibility: VisibilityClass;
  readonly reasons: readonly string[];
}

export interface ClassifiedObservation {
  readonly truncated: boolean;
  readonly nodes: readonly ClassifiedNode[];
  readonly comments: readonly string[];
  readonly metadata: ProbeMetadata;
  readonly links: readonly ProbeLink[];
}

const METADATA_TAGS = new Set(["meta", "link", "title", "base", "head"]);
const CODE_TAGS = new Set(["script", "style", "template", "code", "pre"]);

const HIDDEN_CLASSES: ReadonlySet<VisibilityClass> = new Set([
  "HIDDEN",
  "OFFSCREEN",
  "ZERO_SIZE",
  "ACCESSIBILITY_ONLY",
  "CSS_GENERATED",
]);

const VISIBLE_CLASSES: ReadonlySet<VisibilityClass> = new Set([
  "VISIBLE",
  "VISIBLE_LOW_CONFIDENCE",
]);

export function isHiddenClass(v: VisibilityClass): boolean {
  return HIDDEN_CLASSES.has(v);
}

export function isVisibleClass(v: VisibilityClass): boolean {
  return VISIBLE_CLASSES.has(v);
}

/** Deterministic classification of a single probe node (PRD §13.1). */
export function classifyNode(node: ProbeNode): ClassifiedNode {
  const tag = node.tagName;
  if (tag.length === 0 || node.display.length === 0 || node.visibility.length === 0) {
    return { node, visibility: "UNKNOWN", reasons: ["missing-probe-signal"] };
  }
  if (tag === "noscript") {
    return { node, visibility: "HIDDEN", reasons: ["noscript"] };
  }
  if (CODE_TAGS.has(tag)) {
    return { node, visibility: "SCRIPT_OR_CODE", reasons: ["tag"] };
  }
  if (METADATA_TAGS.has(tag)) {
    return { node, visibility: "METADATA", reasons: ["tag"] };
  }
  if (tag === "iframe" || tag === "frame") {
    return { node, visibility: "EMBEDDED_FRAME", reasons: ["tag"] };
  }

  const reasons: string[] = [];
  if (node.hidden) {
    reasons.push("hidden-attribute");
  }
  if (node.ariaHidden) {
    reasons.push("aria-hidden");
  }
  if (node.display === "none") {
    reasons.push("display-none");
  }
  if (node.visibility === "hidden" || node.visibility === "collapse") {
    reasons.push("visibility-hidden");
  }
  if (node.opacity === 0) {
    reasons.push("opacity-zero");
  }
  if (reasons.length > 0) {
    return { node, visibility: "HIDDEN", reasons };
  }

  if (node.display === "contents") {
    return { node, visibility: "CSS_GENERATED", reasons: ["display-contents"] };
  }

  if (isCollapsedTransform(node.transform)) {
    return { node, visibility: "HIDDEN", reasons: ["collapsed-transform"] };
  }

  if (node.pseudoBefore !== null || node.pseudoAfter !== null) {
    return { node, visibility: "CSS_GENERATED", reasons: ["pseudo-content"] };
  }

  if (node.dimensions === null || node.dimensions.width === 0 || node.dimensions.height === 0) {
    return { node, visibility: "ZERO_SIZE", reasons: ["zero-size"] };
  }

  const onePixelClip =
    node.dimensions.width <= 2 &&
    node.dimensions.height <= 2 &&
    (node.role !== null ||
      node.ariaLabel !== null ||
      node.text.trim().length > 0 ||
      (node.clipPath !== null && node.clipPath !== "none"));
  if (onePixelClip) {
    return { node, visibility: "ACCESSIBILITY_ONLY", reasons: ["clip-pattern"] };
  }

  if (!node.inViewport || isOffscreen(node.boundingBox)) {
    return {
      node,
      visibility: "OFFSCREEN",
      reasons: [node.inViewport ? "extreme-position" : "outside-viewport"],
    };
  }

  if (
    node.dimensions.width < 2 ||
    node.dimensions.height < 2 ||
    (node.fontSize !== null && Number.parseFloat(node.fontSize) <= 1)
  ) {
    return { node, visibility: "ACCESSIBILITY_ONLY", reasons: ["tiny"] };
  }

  return { node, visibility: "VISIBLE", reasons: [] };
}

function isCollapsedTransform(transform: string | null): boolean {
  if (transform === null || transform === "none") return false;
  const values = transform
    .match(/^matrix\(([^)]+)\)$/u)?.[1]
    ?.split(",")
    .map(Number);
  return (
    values !== undefined && values.length >= 4 && values.slice(0, 4).every((value) => value === 0)
  );
}

/** Approximate off-screen detection: extreme positioning (no viewport in probe). */
function isOffscreen(box: ProbeNode["boundingBox"]): boolean {
  if (box === null) {
    return false;
  }
  return box.x < -5000 || box.y < -5000 || box.x > 100_000 || box.y > 100_000;
}

/** Classify a whole probe result. A truncated probe downgrades trust (INV-09). */
export function classifyObservation(probe: ProbeResult): ClassifiedObservation {
  return {
    truncated: probe.truncated,
    nodes: probe.nodes.map((node) => {
      const classified = classifyNode(node);
      if (!probe.truncated || classified.visibility !== "VISIBLE") {
        return classified;
      }
      return {
        ...classified,
        visibility: "VISIBLE_LOW_CONFIDENCE",
        reasons: ["probe-truncated"],
      };
    }),
    comments: probe.comments,
    metadata: probe.metadata,
    links: probe.links,
  };
}

/** Text of only the visible nodes (the safe, agent-facing representation). */
export function visibleText(classified: ClassifiedObservation): string {
  return classified.nodes
    .filter((c) => isVisibleClass(c.visibility))
    .map((c) => c.node.text.trim())
    .filter((t) => t.length > 0)
    .join("\n");
}
