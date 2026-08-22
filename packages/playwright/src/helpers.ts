import { randomUUID } from "node:crypto";
import type { Page } from "playwright";

export type HelperArgument =
  | null
  | boolean
  | number
  | string
  | readonly HelperArgument[]
  | { readonly [key: string]: HelperArgument };

/** Trusted TB1 registration for a deliberately narrow browser helper. */
export interface PlaywrightHelperDefinition {
  readonly name: string;
  readonly sha256: string;
  readonly execute: (page: Page, args: HelperArgument) => Promise<void> | void;
}

const MAX_ARGUMENT_BYTES = 4_096;
const MAX_ARGUMENT_DEPTH = 8;

/** Immutable application-owned registry; helper functions never enter actions or traces. */
export class PlaywrightHelperRegistry {
  readonly id = randomUUID();
  private readonly entries: ReadonlyMap<string, PlaywrightHelperDefinition>;

  constructor(definitions: readonly PlaywrightHelperDefinition[]) {
    const entries = new Map<string, PlaywrightHelperDefinition>();
    for (const definition of definitions) {
      if (
        !/^[a-z][a-z0-9_.-]{0,63}$/.test(definition.name) ||
        !/^[a-f0-9]{64}$/i.test(definition.sha256) ||
        typeof definition.execute !== "function" ||
        entries.has(definition.name)
      ) {
        throw new TypeError("invalid or duplicate application helper registration");
      }
      entries.set(definition.name, Object.freeze({ ...definition }));
    }
    this.entries = entries;
    Object.freeze(this);
  }

  get(name: string): PlaywrightHelperDefinition | undefined {
    return this.entries.get(name);
  }

  resolve(name: string, sha256: string): PlaywrightHelperDefinition | undefined {
    const definition = this.entries.get(name);
    return definition?.sha256 === sha256 ? definition : undefined;
  }

  validateArgs(value: unknown): HelperArgument {
    if (!isHelperArgument(value, 0))
      throw new TypeError("helper arguments must be bounded JSON data");
    if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_ARGUMENT_BYTES) {
      throw new RangeError("helper arguments exceed 4096 bytes");
    }
    return freezeArgument(value);
  }
}

function isHelperArgument(value: unknown, depth: number): value is HelperArgument {
  if (depth > MAX_ARGUMENT_DEPTH) return false;
  if (value === null || typeof value === "boolean" || typeof value === "string") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every((item) => isHelperArgument(item, depth + 1));
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) return false;
  return Object.entries(value).every(
    ([key, item]) => key.length <= 128 && isHelperArgument(item, depth + 1),
  );
}

function freezeArgument(value: HelperArgument): HelperArgument {
  if (value === null) return value;
  if (Array.isArray(value)) return Object.freeze(value.map(freezeArgument));
  if (typeof value === "object") {
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([key, item]) => [key, freezeArgument(item)])),
    );
  }
  return value;
}
