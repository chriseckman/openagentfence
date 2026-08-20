import { DEFAULT_DECODE_LIMITS, type DecodeLimits } from "./limits.js";

function printableRatio(text: string): number {
  if (text.length === 0) {
    return 1;
  }
  let printable = 0;
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127)) {
      printable += 1;
    }
  }
  return printable / text.length;
}

/** Decode a Base64 string; returns null when it is not plausibly Base64 text. */
export function decodeBase64(input: string): string | null {
  const cleaned = input.replace(/\s+/g, "");
  if (cleaned.length === 0 || cleaned.length % 4 !== 0) {
    return null;
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned)) {
    return null;
  }
  try {
    const decoded = Buffer.from(cleaned, "base64").toString("utf8");
    if (printableRatio(decoded) < 0.9) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

/** Decode a hexadecimal string; returns null when not plausibly hex text. */
export function decodeHex(input: string): string | null {
  const cleaned = input.replace(/\s+/g, "");
  if (cleaned.length === 0 || cleaned.length % 2 !== 0) {
    return null;
  }
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
    return null;
  }
  try {
    const buf = Buffer.from(cleaned, "hex");
    const decoded = buf.toString("utf8");
    if (printableRatio(decoded) < 0.9) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

export function decodeUrlEncoded(input: string): string {
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

const HTML_ENTITIES: Readonly<Record<string, string>> = {
  "&lt;": "<",
  "&gt;": ">",
  "&amp;": "&",
  "&quot;": '"',
  "&#39;": "'",
  "&apos;": "'",
  "&nbsp;": " ",
  "&#x27;": "'",
};

export function decodeHtmlEntities(input: string): string {
  let out = input;
  for (const [entity, value] of Object.entries(HTML_ENTITIES)) {
    out = out.split(entity).join(value);
  }
  // numeric character references
  out = out.replace(/&#(\d+);/g, (_, num: string) => {
    const code = Number.parseInt(num, 10);
    return code > 31 && code < 127 ? String.fromCodePoint(code) : " ";
  });
  out = out.replace(/&#x([0-9a-fA-F]+);/g, (_, hex: string) => {
    const code = Number.parseInt(hex, 16);
    return code > 31 && code < 127 ? String.fromCodePoint(code) : " ";
  });
  return out;
}

/**
 * Iteratively apply reversible decodings up to `maxDecodeDepth`, with size and
 * deadline limits (INV-16). Returns the decoded text and the chain of codecs
 * applied.
 */
export interface DecodeOutcome {
  readonly text: string;
  readonly chain: readonly string[];
  /** A refused decode is security-relevant and must never be treated as clean. */
  readonly status: "unchanged" | "decoded" | "refused";
  readonly reason?:
    "input_too_large" | "output_too_large" | "depth_exhausted" | "deadline_exceeded";
}

export function decodeIterative(
  input: string,
  maxDepth: number = DEFAULT_DECODE_LIMITS.maxDecodeDepth,
  deadlineMs: number = DEFAULT_DECODE_LIMITS.deadlineMs,
  limits: DecodeLimits = DEFAULT_DECODE_LIMITS,
): DecodeOutcome {
  const inputBytes = Buffer.byteLength(input, "utf8");
  if (inputBytes > limits.maxInputBytes) {
    return { text: "", chain: [], status: "refused", reason: "input_too_large" };
  }
  // This measures decoder work, not elapsed wall time. The orchestrator owns
  // wall-clock cancellation for the asynchronous scanner invocation.
  const startCpu = process.cpuUsage();
  let current = input;
  const chain: string[] = [];
  for (let depth = 0; depth < maxDepth; depth += 1) {
    if (cpuMicrosecondsSince(startCpu) > deadlineMs * 1_000) {
      // The final permitted reversible step has a deterministic structural
      // outcome when another decode is already evident. Prefer that bounded
      // depth refusal over process-wide CPU noise from a neighboring worker;
      // earlier exhaustion still returns the accepted CPU-budget refusal.
      if (depth === maxDepth - 1 && canDecodeFurther(current)) {
        return { text: current, chain, status: "refused", reason: "depth_exhausted" };
      }
      return { text: current, chain, status: "refused", reason: "deadline_exceeded" };
    }
    let next: string | null = null;
    let codec = "";
    if (/^https?%[0-9A-Fa-f]{2}/.test(current)) {
      next = decodeUrlEncoded(current);
      codec = "url";
    } else if (/^[A-Za-z0-9+/]+={0,2}$/.test(current.replace(/\s+/g, "")) && current.length > 4) {
      next = decodeBase64(current);
      codec = "base64";
    } else if (
      /^[0-9a-fA-F]+$/.test(current.replace(/\s+/g, "")) &&
      current.length > 4 &&
      current.length % 2 === 0
    ) {
      next = decodeHex(current);
      codec = "hex";
    } else if (current.includes("&#")) {
      next = decodeHtmlEntities(current);
      codec = "entities";
    }
    if (next === null || next === current) {
      break;
    }
    if (Buffer.byteLength(next, "utf8") > limits.maxOutputBytes) {
      return { text: current, chain, status: "refused", reason: "output_too_large" };
    }
    current = next;
    chain.push(codec);
  }
  if (chain.length === maxDepth && canDecodeFurther(current)) {
    return { text: current, chain, status: "refused", reason: "depth_exhausted" };
  }
  return { text: current, chain, status: chain.length === 0 ? "unchanged" : "decoded" };
}

function cpuMicrosecondsSince(start: NodeJS.CpuUsage): number {
  const current = process.cpuUsage();
  return current.user - start.user + (current.system - start.system);
}

function canDecodeFurther(value: string): boolean {
  const compact = value.replace(/\s+/g, "");
  return (
    /^https?%[0-9A-Fa-f]{2}/.test(value) ||
    (/^[A-Za-z0-9+/]+={0,2}$/.test(compact) && compact.length > 4) ||
    (/^[0-9a-fA-F]+$/.test(compact) && compact.length > 4 && compact.length % 2 === 0) ||
    value.includes("&#")
  );
}
