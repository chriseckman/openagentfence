import type { Frame, Page, Request, Route } from "playwright";
import {
  buildProbeScript,
  compareIntentState,
  isAuthorizedAction,
  isIntentExpired,
  validateNetworkMutation,
  validateProbeResult,
  type AdapterEventSink,
  type Authorized,
  type BrowserAdapter,
  type BrowserAdapterCapabilities,
  type NetworkCapabilities,
  type NetworkMutation,
  type PageObservation,
  type SecretResolver,
} from "@openagentfence/core";
import { currentState, type PlaywrightOperation, type PlaywrightUploadFile } from "./wrap.js";
import { PlaywrightHelperRegistry, type HelperArgument } from "./helpers.js";

/** Fail-closed result of adapter-local state revalidation (ADR-0010). */
export class PlaywrightRevalidationError extends Error {
  readonly reason: "action_intent_expired" | "action_intent_mismatch" | "action_policy_mismatch";

  constructor(reason: PlaywrightRevalidationError["reason"]) {
    super(reason);
    this.name = "PlaywrightRevalidationError";
    this.reason = reason;
  }
}

export interface PlaywrightAdapterOptions {
  readonly captureScreenshot?: boolean;
  readonly maxScreenshotBytes?: number;
  /** Opt in to pre-request destination enforcement through Playwright routing. */
  readonly routeRequests?: boolean;
  /** Immutable TB1 registry for exact application-owned helper execution. */
  readonly helpers?: PlaywrightHelperRegistry;
}

/**
 * Capability snapshot for lockfile-pinned Playwright 1.62.1 with routing disabled. Request
 * events observe navigation, fetch/XHR, and WebSocket handshakes, but do not
 * prove a form/beacon/upload initiator or permit enforcement. Event-only
 * popup/download support is deliberately not promoted to NetworkMutation.
 */
export const PLAYWRIGHT_NETWORK_CAPABILITIES: NetworkCapabilities = Object.freeze({
  navigation: "observed_only",
  redirect: "unavailable",
  form: "unavailable",
  fetch: "observed_only",
  headers: "unavailable",
  websocket: "observed_only",
  send_beacon: "unavailable",
  service_worker: "unavailable",
  upload: "unavailable",
  download: "unavailable",
  popup: "unavailable",
  webmcp: "unavailable",
});

const PLAYWRIGHT_ROUTED_NETWORK_CAPABILITIES: NetworkCapabilities = Object.freeze({
  navigation: "enforced",
  // Playwright routing invokes a handler only for the first URL in a redirect
  // chain; later hops are observable through request events but cannot be
  // aborted before transmission.
  redirect: "observed_only",
  form: "observed_only",
  fetch: "enforced",
  headers: "observed_only",
  websocket: "observed_only",
  send_beacon: "observed_only",
  service_worker: "unavailable",
  upload: "observed_only",
  download: "observed_only",
  popup: "unavailable",
  webmcp: "unavailable",
});

/** Playwright observation/event adapter. All browser-derived output is TB2 web data. */
export function playwrightAdapter(
  page: Page,
  options: PlaywrightAdapterOptions = {},
): BrowserAdapter {
  const contextId = `pw-context-${Math.random().toString(36).slice(2, 10)}`;
  const pageIds = new WeakMap<Page, string>();
  const frameIds = new WeakMap<Frame, string>();
  const revisions = new WeakMap<Page, number>();
  let nextPageId = 0;
  let nextFrameId = 0;
  const pageId = (value: Page): string => {
    const known = pageIds.get(value);
    if (known !== undefined) return known;
    const assigned = `pw-page-${++nextPageId}`;
    pageIds.set(value, assigned);
    return assigned;
  };
  const frameId = (value: Frame): string => {
    const known = frameIds.get(value);
    if (known !== undefined) return known;
    const assigned = `pw-frame-${++nextFrameId}`;
    frameIds.set(value, assigned);
    return assigned;
  };
  const revision = (value: Page): number => revisions.get(value) ?? 0;
  pageId(page);
  revisions.set(page, 0);
  return {
    capabilities: capabilitiesFor(options),
    async observe(): Promise<PageObservation> {
      const url = page.url();
      const origin = originOfUrl(url);
      const frames = await Promise.all(page.frames().map((frame) => observeFrame(frame, frameId)));
      const main = frames[0];
      if (main?.probe === undefined)
        throw new TypeError("playwright adapter: main-frame probe unavailable");
      const ariaSnapshot = await page.locator("body").ariaSnapshot();
      let screenshot: string | undefined;
      if (options.captureScreenshot === true) {
        const bytes = await page.screenshot({ type: "png" });
        if (bytes.length > (options.maxScreenshotBytes ?? 1_000_000)) {
          throw new RangeError("playwright adapter: screenshot exceeds configured byte limit");
        }
        screenshot = bytes.toString("base64");
      }
      return {
        pageId: pageId(page),
        contextId,
        revision: revision(page),
        url,
        origin,
        frames,
        probe: main.probe,
        ariaSnapshot,
        ...(screenshot !== undefined ? { screenshot } : {}),
        provenance: { trust: "web" },
      };
    },
    async executeAuthorized(authorized: Authorized, resolver: SecretResolver): Promise<unknown> {
      void resolver;
      if (!isAuthorizedAction(authorized)) {
        throw new TypeError("playwright adapter requires a core-minted AuthorizedAction");
      }
      const action = authorized.action;
      const operation = parseOperation(action.raw);
      if (operation === undefined) {
        throw new TypeError("playwright adapter requires a validated exact operation");
      }
      if (isIntentExpired(authorized.intent)) {
        throw new PlaywrightRevalidationError("action_intent_expired");
      }
      if (authorized.policyHash !== authorized.intent.policyHash) {
        throw new PlaywrightRevalidationError("action_policy_mismatch");
      }
      const observation: PageObservation = {
        pageId: pageId(page),
        contextId,
        revision: revision(page),
        url: page.url(),
        origin: originOfUrl(page.url()),
        frames: [],
        provenance: { trust: "web" },
      };
      const state = await currentState(page, observation, operation, authorized.policyHash);
      if (compareIntentState(authorized.intent, state).length > 0) {
        throw new PlaywrightRevalidationError("action_intent_mismatch");
      }
      switch (operation.method) {
        case "helper": {
          const helper = operation.helper;
          if (helper === undefined || options.helpers?.id !== helper.registryId) {
            throw new TypeError("playwright helper registry mismatch");
          }
          const registered = options.helpers.resolve(helper.name, helper.sha256);
          if (registered === undefined) throw new TypeError("playwright helper is not registered");
          await registered.execute(
            page,
            options.helpers.validateArgs(parseHelperArgument(requiredArgument(operation))),
          );
          return undefined;
        }
        case "goto":
          await page.goto(requiredArgument(operation));
          return undefined;
        case "click":
          await page.locator(requiredSelector(operation)).click();
          return undefined;
        case "fill":
          await page.locator(requiredSelector(operation)).fill(requiredArgument(operation));
          return undefined;
        case "type":
          await page
            .locator(requiredSelector(operation))
            .pressSequentially(requiredArgument(operation));
          return undefined;
        case "press":
          await page.locator(requiredSelector(operation)).press(requiredArgument(operation));
          return undefined;
        case "selectOption":
          await page.locator(requiredSelector(operation)).selectOption(requiredArgument(operation));
          return undefined;
        case "setInputFiles":
          await page
            .locator(requiredSelector(operation))
            .setInputFiles(requiredFiles(operation).map(toPlaywrightUploadFile));
          return undefined;
        case "download":
          await page.locator(requiredSelector(operation)).click();
          return undefined;
      }
    },
    subscribe(sessionId: string, sink: AdapterEventSink): () => void {
      if (sessionId.length === 0) throw new TypeError("sessionId must be non-empty");
      const event = (
        kind: "navigation" | "popup" | "download",
        eventPage: Page,
        eventFrame?: Frame,
        url?: string,
      ): void => {
        const value = url ?? eventPage.url();
        const data = {
          kind,
          sessionId,
          url: bounded(value),
          origin: bounded(originOfUrl(value)),
          pageId: pageId(eventPage),
          ...(eventFrame !== undefined ? { frameId: frameId(eventFrame) } : {}),
          revision: revision(eventPage),
        };
        if (kind === "navigation") sink.onNavigation(data);
        else if (kind === "popup") sink.onPopup(data);
        else sink.onDownload(data);
      };
      const listeners: Array<() => void> = [];
      if (options.routeRequests === true) {
        const onRoute = async (route: Route): Promise<void> => {
          const mutation = requestMutation(route.request(), PLAYWRIGHT_ROUTED_NETWORK_CAPABILITIES);
          const decision = mutation === null ? undefined : sink.onRouteRequest?.(mutation);
          if (mutation !== null) sink.onNetworkMutation?.(mutation);
          if (decision?.verdict === "block") {
            await route.abort("blockedbyclient");
            return;
          }
          await route.continue();
        };
        void page.route("**/*", onRoute).catch(() => undefined);
        listeners.push(() => {
          void page.unroute("**/*", onRoute).catch(() => undefined);
        });
      }
      const attach = (watchedPage: Page): void => {
        const onFrame = (frame: Frame): void => {
          revisions.set(watchedPage, revision(watchedPage) + 1);
          event("navigation", watchedPage, frame, frame.url());
        };
        const onDownload = (download: { url(): string }): void =>
          event("download", watchedPage, undefined, download.url());
        const onRequest = (request: Request): void => {
          const mutation = requestMutation(
            request,
            options.routeRequests === true
              ? PLAYWRIGHT_ROUTED_NETWORK_CAPABILITIES
              : PLAYWRIGHT_NETWORK_CAPABILITIES,
          );
          if (mutation !== null) sink.onNetworkMutation?.(mutation);
        };
        watchedPage.on("framenavigated", onFrame);
        watchedPage.on("download", onDownload);
        watchedPage.on("request", onRequest);
        listeners.push(() => {
          watchedPage.off("framenavigated", onFrame);
          watchedPage.off("download", onDownload);
          watchedPage.off("request", onRequest);
        });
      };
      const onPopup = (popup: Page): void => {
        pageId(popup);
        revisions.set(popup, 0);
        const url = popup.url();
        const close = sink.onPopup({
          kind: "popup",
          sessionId,
          url: bounded(url),
          origin: bounded(originOfUrl(url)),
          pageId: pageId(popup),
          revision: revision(popup),
        });
        if (close) {
          void popup.close({ runBeforeUnload: false }).catch(() => undefined);
          return;
        }
        attach(popup);
      };
      page.on("popup", onPopup);
      listeners.push(() => page.off("popup", onPopup));
      attach(page);
      return () => {
        for (const detach of listeners) detach();
      };
    },
    rawPage(): unknown {
      return page;
    },
  };
}

async function observeFrame(
  frame: Frame,
  frameId: (frame: Frame) => string,
): Promise<NonNullable<PageObservation["frames"]>[number]> {
  const url = frame.url();
  const origin = originOfUrl(url);
  try {
    const probe = validateProbeResult(await frame.evaluate<unknown>(buildProbeScript()));
    return probe === null
      ? { id: frameId(frame), url, origin, frameOrigin: origin, embedded: true }
      : { id: frameId(frame), url, origin, frameOrigin: origin, probe };
  } catch {
    return { id: frameId(frame), url, origin, frameOrigin: origin, embedded: true };
  }
}

function requestMutation(
  request: Request,
  capabilities: NetworkCapabilities = PLAYWRIGHT_NETWORK_CAPABILITIES,
): NetworkMutation | null {
  const type = request.resourceType();
  const previous = request.redirectedFrom();
  const surface =
    previous !== null
      ? "redirect"
      : type === "document"
        ? "navigation"
        : type === "websocket"
          ? "websocket"
          : "fetch";
  const frameUrl = previous?.url() ?? request.frame().url();
  return validateNetworkMutation({
    surface,
    initiator: previous !== null ? "redirect" : type === "document" ? "unknown" : "page_script",
    origin: bounded(originOfUrl(frameUrl)),
    frameOrigin: bounded(originOfUrl(frameUrl)),
    destination: bounded(request.url()),
    enforcement: capabilities[surface],
    metadata: {
      method: request.method(),
      headers: redactHeaders(request.headers()),
      ...(request.postDataBuffer() !== null ? { bodySize: request.postDataBuffer()?.length } : {}),
    },
    ...(previous !== null ? { redirectHops: redirectHops(request) } : {}),
  });
}
function capabilitiesFor(options: PlaywrightAdapterOptions): BrowserAdapterCapabilities {
  return {
    route: options.routeRequests === true,
    downloadEvents: true,
    popupEvents: true,
    screenshot: options.captureScreenshot === true,
    ariaSnapshot: true,
  };
}

function redirectHops(request: Request): number {
  let hops = 0;
  let current: Request | null = request.redirectedFrom();
  while (current !== null && hops <= 100) {
    hops += 1;
    current = current.redirectedFrom();
  }
  return hops;
}
function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers).slice(0, 32))
    out[key] = /authorization|cookie|token|secret/i.test(key) ? "[REDACTED]" : bounded(value, 256);
  return out;
}
function bounded(value: string, max = 2048): string {
  return value.slice(0, max);
}
function originOfUrl(url: string): string {
  try {
    const origin = new URL(url).origin;
    return origin === "null" ? url : origin;
  } catch {
    return url;
  }
}

function parseOperation(value: unknown): PlaywrightOperation | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const method = record["method"];
  const args = record["arguments"];
  const selector = record["selector"];
  const files = record["files"];
  const helper = record["helper"];
  if (
    record["adapter"] !== "playwright" ||
    ![
      "goto",
      "click",
      "fill",
      "type",
      "press",
      "selectOption",
      "setInputFiles",
      "download",
      "helper",
    ].includes(method as string) ||
    !Array.isArray(args) ||
    !args.every((arg) => typeof arg === "string") ||
    (selector !== undefined && typeof selector !== "string")
  ) {
    return undefined;
  }
  if (
    method !== "goto" &&
    method !== "helper" &&
    (typeof selector !== "string" || selector.length === 0)
  )
    return undefined;
  if (
    (method === "click" || method === "download" || method === "setInputFiles") &&
    args.length !== 0
  )
    return undefined;
  if (!["click", "download", "setInputFiles"].includes(method as string) && args.length !== 1)
    return undefined;
  let parsedFiles: PlaywrightUploadFile[] | undefined;
  if (method === "setInputFiles") {
    if (!Array.isArray(files) || files.length === 0 || !files.every(isUploadFile)) return undefined;
    parsedFiles = files;
  } else if (files !== undefined) {
    return undefined;
  }
  const parsedHelper = method === "helper" ? parseHelperMetadata(helper) : undefined;
  if (method === "helper" && parsedHelper === undefined) return undefined;
  if (method !== "helper" && helper !== undefined) return undefined;
  return Object.freeze({
    adapter: "playwright",
    method: method as PlaywrightOperation["method"],
    ...(typeof selector === "string" ? { selector } : {}),
    arguments: Object.freeze([...args] as string[]),
    ...(parsedFiles !== undefined ? { files: Object.freeze([...parsedFiles]) } : {}),
    ...(parsedHelper !== undefined ? { helper: parsedHelper } : {}),
  });
}

function parseHelperMetadata(
  value: unknown,
): NonNullable<PlaywrightOperation["helper"]> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (
    typeof record["registryId"] !== "string" ||
    typeof record["name"] !== "string" ||
    typeof record["sha256"] !== "string" ||
    !/^[a-z][a-z0-9_.-]{0,63}$/.test(record["name"]) ||
    !/^[a-f0-9]{64}$/i.test(record["sha256"])
  ) {
    return undefined;
  }
  return Object.freeze({
    registryId: record["registryId"],
    name: record["name"],
    sha256: record["sha256"],
  });
}

function parseHelperArgument(value: string): HelperArgument {
  if (value.length > 4_096) throw new TypeError("playwright helper argument exceeds bounds");
  try {
    return JSON.parse(value) as HelperArgument;
  } catch {
    throw new TypeError("playwright helper argument is not valid JSON");
  }
}

function isUploadFile(value: unknown): value is PlaywrightUploadFile {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record["name"] === "string" &&
    record["name"].length > 0 &&
    record["name"].length <= 256 &&
    Buffer.isBuffer(record["buffer"]) &&
    (record["mimeType"] === undefined ||
      (typeof record["mimeType"] === "string" && record["mimeType"].length <= 256))
  );
}

function toPlaywrightUploadFile(file: PlaywrightUploadFile): {
  readonly name: string;
  readonly mimeType: string;
  readonly buffer: Buffer;
} {
  return {
    name: file.name,
    mimeType: file.mimeType ?? "application/octet-stream",
    buffer: file.buffer,
  };
}

function requiredSelector(operation: PlaywrightOperation): string {
  if (operation.selector === undefined || operation.selector.length === 0) {
    throw new TypeError("playwright operation lacks a selector");
  }
  return operation.selector;
}

function requiredArgument(operation: PlaywrightOperation): string {
  const value = operation.arguments[0];
  if (value === undefined) throw new TypeError("playwright operation lacks an argument");
  return value;
}

function requiredFiles(operation: PlaywrightOperation): readonly PlaywrightUploadFile[] {
  if (operation.files === undefined || operation.files.length === 0) {
    throw new TypeError("playwright upload operation lacks files");
  }
  return operation.files;
}
