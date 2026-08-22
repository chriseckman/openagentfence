import { readFileSync } from "node:fs";

interface SeedRegistry {
  readonly schemaVersion: "1.0.0";
  readonly prRuns: number;
  readonly maxRuns: number;
  readonly properties: Readonly<Record<string, number>>;
}

const registry = JSON.parse(
  readFileSync(new URL("../../../../fuzz/seeds.json", import.meta.url), "utf8"),
) as SeedRegistry;

export function propertyOptions(id: string): {
  readonly numRuns: number;
  readonly seed: number;
  readonly path?: string;
} {
  const seed = registry.properties[id];
  const configured = process.env["OAF_PROPERTY_RUNS"];
  const numRuns = configured === undefined ? registry.prRuns : Number(configured);
  if (
    seed === undefined ||
    !Number.isSafeInteger(seed) ||
    !Number.isInteger(numRuns) ||
    numRuns < registry.prRuns ||
    numRuns > registry.maxRuns
  ) {
    throw new RangeError(`invalid property configuration: ${id}`);
  }
  const replay = process.env["OAF_PROPERTY_REPLAY"];
  const prefix = `${id}=`;
  return {
    numRuns,
    seed,
    ...(replay?.startsWith(prefix) === true ? { path: replay.slice(prefix.length) } : {}),
  };
}
