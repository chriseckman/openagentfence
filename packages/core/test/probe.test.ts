import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  buildProbeScript,
  DEFAULT_PROBE_OPTIONS,
  PROBE_SCRIPT,
  PROBE_VERSION,
  validateProbeResult,
} from "../src/index.js";
import type { ProbeResult } from "../src/index.js";

function mkNode(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    selector: "#a",
    tagName: "div",
    text: "hello",
    display: "block",
    visibility: "visible",
    opacity: 1,
    ariaHidden: false,
    hidden: false,
    role: null,
    ariaLabel: null,
    ariaDescription: null,
    attributes: {},
    dimensions: { x: 0, y: 0, width: 10, height: 10 },
    boundingBox: { x: 0, y: 0, width: 10, height: 10 },
    frameOrigin: "https://example.com",
    fontSize: "16px",
    color: "rgb(0, 0, 0)",
    backgroundColor: "rgba(0, 0, 0, 0)",
    position: "static",
    transform: "none",
    clipPath: "none",
    overflow: "visible",
    inViewport: true,
    pseudoBefore: null,
    pseudoAfter: null,
    ...overrides,
  };
}

function mkProbe(overrides: Record<string, unknown> = {}): ProbeResult {
  const probe = {
    probeVersion: PROBE_VERSION,
    truncated: false,
    truncation: {
      nodes: false,
      textBytes: false,
      comments: false,
      metadata: false,
      links: false,
      time: false,
    },
    nodes: [mkNode()],
    comments: [],
    metadata: { title: "t", meta: {}, jsonLd: [], noscript: [] },
    links: [],
    ...overrides,
  } as unknown as ProbeResult;
  return probe;
}

describe("buildProbeScript", () => {
  it("substitutes numeric limits and leaves no placeholders", () => {
    const script = buildProbeScript({ maxNodes: 7, maxTextBytes: 42, timeBudgetMs: 9 });
    expect(script).toContain("maxNodes = 7");
    expect(script).toContain("maxTextBytes = 42");
    expect(script).toContain("timeBudgetMs = 9");
    expect(script).toContain(`probeVersion: ${PROBE_VERSION}`);
    expect(script).not.toMatch(/__[A-Z_]+__/);
  });

  it("applies documented defaults", () => {
    const script = PROBE_SCRIPT;
    expect(script).toContain(`maxNodes = ${DEFAULT_PROBE_OPTIONS.maxNodes}`);
    expect(script).toContain(`maxComments = ${DEFAULT_PROBE_OPTIONS.maxComments}`);
  });

  it("does not eval or construct functions", () => {
    expect(PROBE_SCRIPT).not.toMatch(/\beval\b|new Function/);
  });
});

describe("validateProbeResult", () => {
  it("accepts a valid probe result", () => {
    expect(validateProbeResult(mkProbe())).not.toBeNull();
  });

  it("accepts null dimensions/boxes and nullable string fields", () => {
    const node = mkNode({
      dimensions: null,
      boundingBox: null,
      role: "button",
      fontSize: null,
      pseudoBefore: "before text",
    });
    expect(validateProbeResult(mkProbe({ nodes: [node] }))).not.toBeNull();
  });

  it("rejects malformed results", () => {
    expect(validateProbeResult(null)).toBeNull();
    expect(validateProbeResult({})).toBeNull();
    expect(validateProbeResult(mkProbe({ probeVersion: "1" }))).toBeNull();
    expect(validateProbeResult(mkProbe({ truncated: "yes" }))).toBeNull();
    expect(validateProbeResult(mkProbe({ nodes: "nope" }))).toBeNull();
    expect(validateProbeResult(mkProbe({ nodes: [mkNode({ opacity: "1" })] }))).toBeNull();
    expect(validateProbeResult(mkProbe({ nodes: [mkNode({ inViewport: "yes" })] }))).toBeNull();
    expect(validateProbeResult(mkProbe({ nodes: [mkNode({ extra: true })] }))).toBeNull();
    expect(
      validateProbeResult(mkProbe({ truncation: { nodes: false, textBytes: false } })),
    ).toBeNull();
    expect(validateProbeResult(mkProbe({ metadata: { title: "t" } }))).toBeNull();
    expect(validateProbeResult(mkProbe({ links: [{ text: 1, href: "h" }] }))).toBeNull();
  });

  it("never throws on arbitrary JSON-like input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateProbeResult(value)).not.toThrow();
      }),
    );
  });
});
