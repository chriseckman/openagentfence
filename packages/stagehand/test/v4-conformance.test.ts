import type { Action, ObserveResult, Stagehand } from "@browserbasehq/stagehand";
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
});
