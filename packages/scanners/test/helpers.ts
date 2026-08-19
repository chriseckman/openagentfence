import {
  RedactionRegistry,
  secureDefaultEnvelope,
  type ProbeNode,
  type ProbeResult,
  type SecurityContext,
} from "@openagentfence/core";

export function probe(nodes: readonly ProbeNode[]): ProbeResult {
  return {
    probeVersion: 2,
    truncated: false,
    truncation: {
      nodes: false,
      textBytes: false,
      comments: false,
      metadata: false,
      links: false,
      time: false,
    },
    nodes,
    comments: [],
    metadata: { title: "", meta: {}, jsonLd: [], noscript: [] },
    links: [],
  };
}

export function node(overrides: Partial<ProbeNode> = {}): ProbeNode {
  return {
    selector: "div",
    tagName: "div",
    text: "",
    display: "block",
    visibility: "visible",
    opacity: 1,
    ariaHidden: false,
    hidden: false,
    role: null,
    ariaLabel: null,
    ariaDescription: null,
    attributes: {},
    dimensions: { x: 0, y: 0, width: 100, height: 20 },
    boundingBox: { x: 0, y: 0, width: 100, height: 20 },
    frameOrigin: "https://shop.example",
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

export function scannerContext(probeResult: ProbeResult): SecurityContext {
  return {
    phase: "PERCEPTION",
    sessionId: "test-session",
    taskContract: { task: "test" },
    envelope: secureDefaultEnvelope("test"),
    riskState: "NORMAL",
    payload: {
      kind: "observation",
      observation: {
        url: "https://shop.example",
        origin: "https://shop.example",
        frames: [],
        probe: probeResult,
        provenance: { trust: "web" },
      },
    },
    provenance: { trust: "web" },
    redactor: new RedactionRegistry(),
    deadline: Date.now() + 10_000,
    signal: new AbortController().signal,
  };
}
