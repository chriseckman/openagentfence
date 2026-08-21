import type { Action, ObserveResult, Stagehand } from "@browserbasehq/stagehand";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type {
  StagehandLike,
  StagehandObserveResponse,
  StagehandObserveResult,
} from "../src/index.js";

// These assignments are compile-time conformance checks against the exact
// Stagehand version in devDependencies. Runtime tests use recorded responses
// and never call a model or external service.
const asOpenAgentFenceStagehand = (stagehand: Stagehand): StagehandLike => stagehand;
const asOpenAgentFenceAction = (action: Action): StagehandObserveResult => action;
const asOpenAgentFenceObserveResponse = (result: ObserveResult): StagehandObserveResponse => result;

describe("Stagehand v4 conformance", () => {
  it("keeps the structural adapter surface checked by TypeScript", () => {
    expect(asOpenAgentFenceStagehand).toBeTypeOf("function");
    expect(asOpenAgentFenceAction).toBeTypeOf("function");
    expect(asOpenAgentFenceObserveResponse).toBeTypeOf("function");
  });

  it("pins the exact verified SDK, peer range, and SDK Node floor", () => {
    const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
    const adapterPackage = readPackage(join(packageRoot, "package.json"));
    const sdkPackage = readPackage(
      join(packageRoot, "node_modules", "@browserbasehq", "stagehand", "package.json"),
    );
    expect(sdkPackage["version"]).toBe("4.0.1");
    expect((sdkPackage["engines"] as Record<string, unknown>)["node"]).toBe(">=22.18.0");
    expect(
      (adapterPackage["peerDependencies"] as Record<string, unknown>)["@browserbasehq/stagehand"],
    ).toBe("4.0.1");
    expect((adapterPackage["engines"] as Record<string, unknown>)["node"]).toBe(">=22.18.0");
  });
});

function readPackage(path: string): Readonly<Record<string, unknown>> {
  const value: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("invalid package metadata");
  }
  return value as Readonly<Record<string, unknown>>;
}
