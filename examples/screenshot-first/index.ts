import type { ProvenancedDatum } from "@openagentfence/core";
import type { StagehandLike, StagehandStateResolver } from "@openagentfence/stagehand";
import { secureStagehand } from "../stagehand-local/index.js";
import type { BrowserAdapter, SecurityScanner, TaskContract } from "@openagentfence/core";

export async function screenshotFirstContext(
  adapter: BrowserAdapter,
  stagehand: StagehandLike,
  stateResolver: StagehandStateResolver,
  contract: TaskContract,
  scanners: readonly SecurityScanner[],
): Promise<{ readonly screenshot: unknown; readonly visibleText: ProvenancedDatum<string> }> {
  const secured = secureStagehand(adapter, stagehand, stateResolver, contract, scanners);
  return secured.stagehand.screenshotFirstContext();
}
