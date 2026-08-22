import {
  OpenAgentFence,
  type BrowserAdapter,
  type SecurityScanner,
  type TaskContract,
} from "@openagentfence/core";
import {
  wrapStagehand,
  type StagehandLike,
  type StagehandStateResolver,
} from "@openagentfence/stagehand";

export function secureStagehand(
  adapter: BrowserAdapter,
  stagehand: StagehandLike,
  stateResolver: StagehandStateResolver,
  contract: TaskContract,
  scanners: readonly SecurityScanner[],
) {
  const session = new OpenAgentFence({ adapter, scanners }).start(contract);
  return {
    session,
    stagehand: wrapStagehand(session, stagehand, { stateResolver, selfHeal: false }),
  };
}
