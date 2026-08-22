import { describe, expect, it } from "vitest";
import {
  comparePostAction,
  DEFAULT_NETWORK_CAPABILITIES,
  OpenAgentFence,
  postActionCapabilitiesAvailable,
  type AdapterEventSink,
  type BrowserAdapter,
  type PostActionObservation,
} from "../src/index.js";
import { fakeAdapter, mkAction } from "./helpers.js";

function eventAdapter(
  emit: (sink: AdapterEventSink, sessionId: string) => void,
  capabilities: BrowserAdapter["capabilities"] = {
    route: false,
    network: DEFAULT_NETWORK_CAPABILITIES,
    navigationEvents: true,
    downloadEvents: true,
    popupEvents: true,
    screenshot: false,
    ariaSnapshot: false,
  },
): BrowserAdapter {
  let sink: AdapterEventSink | undefined;
  let sessionId = "";
  return fakeAdapter({
    capabilities,
    subscribe: (id, value) => {
      sessionId = id;
      sink = value;
      return () => {
        sink = undefined;
      };
    },
    executeAuthorized: async () => {
      if (sink === undefined) throw new Error("test adapter was not subscribed");
      emit(sink, sessionId);
    },
  });
}

async function authorizeClick(adapter: BrowserAdapter) {
  const session = new OpenAgentFence({ adapter }).start({ task: "post action fixture" });
  const action = mkAction("CLICK", { target: { origin: "https://shop.example" } });
  const now = Date.now();
  const bound = await session.authorizeBound(action, {
    intentId: "post-action-intent",
    actionId: "post-action-action",
    action,
    observation: { browserContextId: "ctx", pageId: "page", revision: 1 },
    target: { origin: "https://shop.example" },
    securityAttributes: {},
    visibility: "visible",
    policyHash: session.policyEngine.policyHash,
    operationHash: "operation",
    createdAt: now,
    expiresAt: now + 1_000,
  });
  if (bound.authorized === undefined) throw new Error("test action was unexpectedly blocked");
  return { session, authorized: bound.authorized };
}

describe("deterministic POST_ACTION observation", () => {
  it("compares only immutable authorized navigation and download expectations", () => {
    const action = mkAction("NAVIGATE", {
      target: { origin: "https://shop.example" },
      destination: "https://shop.example/account",
    });
    const observation: PostActionObservation = {
      intentId: "i",
      action,
      intent: {
        intentId: "i",
        actionId: "a",
        action,
        observation: { browserContextId: "ctx", pageId: "page", revision: 1 },
        target: { origin: "https://shop.example" },
        securityAttributes: {},
        visibility: "visible",
        policyHash: "policy",
        operationHash: "op",
        createdAt: 0,
        expiresAt: 1,
      },
      startedOrigin: "https://shop.example",
      events: [
        {
          kind: "navigation",
          sessionId: "s",
          pageId: "page",
          mainFrame: true,
          origin: "https://evil.example",
        },
      ],
      status: "complete",
    };
    expect(comparePostAction(observation)).toEqual(["unexpected_redirect"]);
    expect(
      comparePostAction({
        ...observation,
        action: mkAction("DOWNLOAD", { destination: "https://shop.example/file" }),
        events: [{ kind: "download", sessionId: "s", origin: "https://evil.example" }],
      }),
    ).toEqual(["unexpected_download"]);
    expect(comparePostAction({ ...observation, events: [], status: "cancelled" })).toEqual([
      "post_action_observation_cancelled",
    ]);
    expect(
      postActionCapabilitiesAvailable({
        route: false,
        network: DEFAULT_NETWORK_CAPABILITIES,
        navigationEvents: true,
        downloadEvents: true,
        popupEvents: false,
        screenshot: false,
        ariaSnapshot: false,
      }),
    ).toBe(false);
  });

  it("records a cross-origin top-level navigation as an unexpected origin change", async () => {
    const adapter = eventAdapter((sink, sessionId) =>
      sink.onNavigation({
        kind: "navigation",
        sessionId,
        pageId: "page",
        mainFrame: true,
        origin: "https://evil.example",
        url: "https://evil.example/collect",
      }),
    );
    const { session, authorized } = await authorizeClick(adapter);
    await session.executeAuthorized(authorized);
    expect(session.riskScore).toBeGreaterThan(0);
    const trace = await session.end();
    expect(JSON.stringify(trace)).toContain("unexpected_origin_change");
  });

  it("does not treat an iframe navigation as a top-level origin change", async () => {
    const adapter = eventAdapter((sink, sessionId) =>
      sink.onNavigation({
        kind: "navigation",
        sessionId,
        pageId: "page",
        frameId: "iframe",
        mainFrame: false,
        origin: "https://evil.example",
      }),
    );
    const { session, authorized } = await authorizeClick(adapter);
    await session.executeAuthorized(authorized);
    expect(session.riskScore).toBe(0);
    const trace = await session.end();
    expect(JSON.stringify(trace)).not.toContain("unexpected_origin_change");
  });

  it("detects an unexpected popup and download after exact execution", async () => {
    const adapter = eventAdapter((sink, sessionId) => {
      sink.onPopup({ kind: "popup", sessionId, pageId: "popup", origin: "https://shop.example" });
      sink.onDownload({
        kind: "download",
        sessionId,
        pageId: "page",
        origin: "https://shop.example",
        url: "https://shop.example/file.bin",
      });
    });
    const { session, authorized } = await authorizeClick(adapter);
    await session.executeAuthorized(authorized);
    const trace = await session.end();
    const serialized = JSON.stringify(trace);
    expect(serialized).toContain("unexpected_tab");
    expect(serialized).toContain("unexpected_download");
  });

  it("restricts subsequent authority instead of reporting a clean result when observation is unavailable", async () => {
    const adapter = eventAdapter(() => undefined, {
      route: false,
      network: DEFAULT_NETWORK_CAPABILITIES,
      navigationEvents: false,
      downloadEvents: false,
      popupEvents: false,
      screenshot: false,
      ariaSnapshot: false,
    });
    const { session, authorized } = await authorizeClick(adapter);
    await session.executeAuthorized(authorized);
    expect(session.riskState).toBe("RESTRICTED");
    const trace = await session.end();
    expect(JSON.stringify(trace)).toContain("post_action_observation_unavailable");
  });

  it("fails closed for subsequent authority when the bounded event queue overflows", async () => {
    const adapter = eventAdapter((sink, sessionId) => {
      for (let index = 0; index < 33; index += 1) {
        sink.onPopup({
          kind: "popup",
          sessionId,
          pageId: `popup-${index}`,
          origin: "https://shop.example",
        });
      }
    });
    const { session, authorized } = await authorizeClick(adapter);
    await session.executeAuthorized(authorized);
    expect(session.riskState).toBe("RESTRICTED");
    const trace = await session.end();
    expect(JSON.stringify(trace)).toContain("post_action_observation_overflow");
  });
});
