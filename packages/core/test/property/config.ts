import { readFileSync } from "node:fs";

interface SeedRegistry {
  readonly schemaVersion: "1.0.0";
  readonly prRuns: number;
  readonly nightlyRuns: number;
  readonly maxRuns: number;
  readonly properties: Readonly<Record<string, number>>;
}

const registry = loadRegistry();

export function propertyOptions(id: string): {
  readonly numRuns: number;
  readonly seed: number;
  readonly path?: string;
} {
  const seed = registry.properties[id];
  if (seed === undefined || !Number.isSafeInteger(seed)) {
    throw new TypeError(`missing property seed: ${id}`);
  }
  const configured = process.env["OAF_PROPERTY_RUNS"];
  const numRuns = configured === undefined ? registry.prRuns : Number(configured);
  if (!Number.isInteger(numRuns) || numRuns < registry.prRuns || numRuns > registry.maxRuns) {
    throw new RangeError("OAF_PROPERTY_RUNS is outside the registered property bounds");
  }
  const replay = process.env["OAF_PROPERTY_REPLAY"];
  const prefix = `${id}=`;
  return {
    numRuns,
    seed,
    ...(replay?.startsWith(prefix) === true ? { path: replay.slice(prefix.length) } : {}),
  };
}

function loadRegistry(): SeedRegistry {
  const value = JSON.parse(
    readFileSync(new URL("../../../../fuzz/seeds.json", import.meta.url), "utf8"),
  ) as unknown;
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    (value as { schemaVersion?: unknown }).schemaVersion !== "1.0.0"
  ) {
    throw new TypeError("invalid property seed registry");
  }
  const candidate = value as Partial<SeedRegistry>;
  if (
    !Number.isInteger(candidate.prRuns) ||
    !Number.isInteger(candidate.nightlyRuns) ||
    !Number.isInteger(candidate.maxRuns) ||
    candidate.properties === undefined ||
    typeof candidate.properties !== "object"
  ) {
    throw new TypeError("invalid property seed registry bounds");
  }
  return candidate as SeedRegistry;
}
