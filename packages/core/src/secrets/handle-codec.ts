import { randomBytes } from "node:crypto";

export const HANDLE_KINDS = ["SECRET", "PII", "CREDENTIAL"] as const;

export type SecretHandleKind = (typeof HANDLE_KINDS)[number];

/**
 * Opaque secret handle `<SECRET:name:shortid>` (ADR-0005). Carries no
 * recoverable information; the raw value resolves only executor-side for a
 * bound sink.
 */
export interface SecretHandle {
  readonly kind: SecretHandleKind;
  readonly name: string;
  readonly id: string;
}

const HANDLE_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,96}$/;
const HANDLE_ID_PATTERN = /^[a-f0-9]{32}$/;
const HANDLE_PATTERN = /<([A-Z]+):([A-Za-z0-9_.-]{1,96}):([a-f0-9]{32})>/g;

/** Parse a handle literal; returns null when the string is not exactly one handle. */
export function parseHandle(text: string): SecretHandle | null {
  const trimmed = text.trim();
  const match = /^<([A-Z]+):([^:>]+):([^:>]+)>$/.exec(trimmed);
  if (match === null) {
    return null;
  }
  const kind = match[1];
  const name = match[2];
  const id = match[3];
  if (kind === undefined || name === undefined || id === undefined) {
    return null;
  }
  if (!(HANDLE_KINDS as readonly string[]).includes(kind)) {
    return null;
  }
  if (!HANDLE_NAME_PATTERN.test(name) || !HANDLE_ID_PATTERN.test(id)) {
    return null;
  }
  return { kind: kind as SecretHandleKind, name, id };
}

export function serializeHandle(handle: SecretHandle): string {
  if (!HANDLE_NAME_PATTERN.test(handle.name) || !HANDLE_ID_PATTERN.test(handle.id)) {
    throw new TypeError("invalid secret handle");
  }
  return `<${handle.kind}:${handle.name}:${handle.id}>`;
}

/** Mint a handle with a random short id (used by vault implementations). */
export function mintHandle(kind: SecretHandleKind, name: string): SecretHandle {
  if (!HANDLE_NAME_PATTERN.test(name)) {
    throw new TypeError("secret handle name must use up to 96 letters, digits, '.', '_' or '-'");
  }
  return { kind, name, id: randomBytes(16).toString("hex") };
}

/**
 * Find every secret handle embedded in a string or in nested structured data
 * (URLs, form data, headers, file paths, objects, arrays). Bounded depth to
 * prevent pathological inputs (INV-16).
 */
export function detectHandles(data: unknown, maxDepth = 8): SecretHandle[] {
  const found: SecretHandle[] = [];
  collect(data, 0, maxDepth, found);
  return found;
}

function collect(value: unknown, depth: number, maxDepth: number, out: SecretHandle[]): void {
  if (depth > maxDepth) {
    return;
  }
  if (typeof value === "string") {
    HANDLE_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = HANDLE_PATTERN.exec(value)) !== null) {
      const kind = match[1] ?? "";
      if ((HANDLE_KINDS as readonly string[]).includes(kind)) {
        out.push({ kind: kind as SecretHandleKind, name: match[2] ?? "", id: match[3] ?? "" });
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collect(item, depth + 1, maxDepth, out);
    }
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const key of Object.keys(value)) {
      collect((value as Record<string, unknown>)[key], depth + 1, maxDepth, out);
    }
  }
}
