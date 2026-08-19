import type { Download, Page } from "playwright";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  fingerprint,
  type ActionIntent,
  type CanonicalAction,
  type IntentStateSnapshot,
  type PageObservation,
  type SecuritySession,
} from "@openagentfence/core";
import { PlaywrightHelperRegistry } from "./helpers.js";

const INTENT_TTL_MS = 5_000;

/** Exact operation data passed across the Playwright adapter boundary. */
export interface PlaywrightOperation {
  readonly adapter: "playwright";
  readonly method:
    | "goto"
    | "click"
    | "fill"
    | "type"
    | "press"
    | "selectOption"
    | "setInputFiles"
    | "download"
    | "helper";
  readonly selector?: string;
  readonly arguments: readonly string[];
  readonly files?: readonly PlaywrightUploadFile[];
  readonly helper?: { readonly registryId: string; readonly name: string; readonly sha256: string };
}

/** Application-provided in-memory upload data. Filesystem paths are excluded. */
export interface PlaywrightUploadFile {
  readonly name: string;
  readonly buffer: Buffer;
  readonly mimeType?: string;
}

export interface UploadOptions {
  readonly provenance: "application" | "user";
  readonly sensitivity: "public" | "sensitive";
  readonly taskNecessary: true;
}

export interface DownloadMetadata {
  readonly sourceOrigin: string;
  readonly mimeType: string;
  readonly filename: string;
  readonly sha256: string;
  readonly disposition: string;
  readonly bytes: number;
}

export interface SecureLocator {
  readonly click: () => Promise<void>;
  readonly fill: (value: string) => Promise<void>;
  readonly type: (value: string) => Promise<void>;
  readonly press: (key: string) => Promise<void>;
  readonly selectOption: (value: string) => Promise<void>;
  readonly setInputFiles: (
    files: readonly PlaywrightUploadFile[],
    options: UploadOptions,
  ) => Promise<void>;
}

/**
 * Guarded Playwright surface (OAF-BROWSER-002/014). It intentionally exposes
 * only operations with complete normalize, authorize, revalidate, and exact
 * execution coverage. Raw handles remain available only through `rawPage()`.
 */
export interface SecurePage {
  readonly goto: (url: string) => Promise<void>;
  readonly click: (selector: string) => Promise<void>;
  readonly download: (selector: string) => Promise<DownloadMetadata>;
  readonly executeHelper: (name: string, args: unknown) => Promise<void>;
  readonly locator: (selector: string) => SecureLocator;
  readonly rawPage: (reason: string) => Page;
}

export function wrapPage(
  session: SecuritySession,
  page: Page,
  helpers?: PlaywrightHelperRegistry,
): SecurePage {
  const execute = async (
    method: PlaywrightOperation["method"],
    selector: string | undefined,
    args: readonly string[],
    files?: readonly PlaywrightUploadFile[],
    data?: unknown,
    helper?: PlaywrightOperation["helper"],
  ): Promise<void> => {
    if (args.some((value) => value.includes("openagentfence://secret/"))) {
      throw new TypeError("secret-handle-bearing Playwright operations are disabled until M4");
    }
    const observation = await session.observe();
    const operation: PlaywrightOperation = Object.freeze({
      adapter: "playwright",
      method,
      ...(selector !== undefined ? { selector } : {}),
      arguments: Object.freeze([...args]),
      ...(files !== undefined ? { files: Object.freeze([...files]) } : {}),
      ...(helper !== undefined ? { helper } : {}),
    });
    const action = await canonicalAction(page, operation, observation.observation, data);
    const state = await currentState(
      page,
      observation.observation,
      operation,
      session.policyEngine.policyHash,
    );
    const now = Date.now();
    const intent: ActionIntent = {
      intentId: `pw-intent-${fingerprint(`${now}:${operation.method}:${operation.selector ?? ""}`)}`,
      actionId: `pw-action-${fingerprint(JSON.stringify(operation))}`,
      action,
      observation: state.observation,
      target: state.target,
      ...(state.frameOrigin !== undefined ? { frameOrigin: state.frameOrigin } : {}),
      ...(state.destination !== undefined ? { destination: state.destination } : {}),
      ...(action.navigationOrigin !== undefined
        ? { navigationOrigin: action.navigationOrigin }
        : {}),
      ...(state.formAction !== undefined ? { formAction: state.formAction } : {}),
      securityAttributes: state.securityAttributes,
      visibility: state.visibility,
      policyHash: state.policyHash,
      operationHash: state.operationHash,
      createdAt: now,
      expiresAt: now + INTENT_TTL_MS,
    };
    const bound = await session.authorizeBound(action, intent);
    if (bound.authorized === undefined) {
      throw new Error(`Playwright operation blocked (${bound.decision.reasons.join(", ")})`);
    }
    await session.executeAuthorized(bound.authorized);
  };

  const locator = (selector: string): SecureLocator => ({
    click: () => execute("click", selector, []),
    fill: (value) => execute("fill", selector, [value]),
    type: (value) => execute("type", selector, [value]),
    press: (key) => execute("press", selector, [key]),
    selectOption: (value) => execute("selectOption", selector, [value]),
    setInputFiles: (files, options) => {
      const validated = validateUploadFiles(files, options);
      return execute(
        "setInputFiles",
        selector,
        [],
        validated,
        Object.freeze({
          files: validated.map((file) => ({
            name: file.name,
            ...(file.mimeType !== undefined ? { mimeType: file.mimeType } : {}),
            bytes: file.buffer.length,
          })),
          provenance: { trust: options.provenance },
          sensitivity: options.sensitivity,
          taskNecessary: options.taskNecessary,
        }),
      );
    },
  });

  return {
    goto: (url) => execute("goto", undefined, [url]),
    click: (selector) => execute("click", selector, []),
    executeHelper: (name, args) => {
      if (helpers === undefined)
        throw new TypeError("no application helper registry is configured");
      const helper = helpers.get(name);
      if (helper === undefined) throw new TypeError("application helper is not registered");
      const validatedArgs = helpers.validateArgs(args);
      return execute(
        "helper",
        undefined,
        [JSON.stringify(validatedArgs)],
        undefined,
        { helper: { name: helper.name, sha256: helper.sha256 } },
        Object.freeze({ registryId: helpers.id, name: helper.name, sha256: helper.sha256 }),
      );
    },
    async download(selector: string): Promise<DownloadMetadata> {
      const response = page.waitForResponse(
        (candidate) => candidate.request().resourceType() === "document",
        { timeout: 5_000 },
      );
      const received = waitForDownload(page);
      await execute("download", selector, []);
      const [download, downloadResponse] = await Promise.all([received, response]);
      const path = await download.path();
      try {
        const bytes = await readFile(path);
        if (!session.reserveBudget([{ kind: "downloadBytes", amount: bytes.length }])) {
          throw new TypeError("download metadata exceeds the remaining session budget");
        }
        const headers = downloadResponse.headers();
        const mimeType = headers["content-type"];
        const disposition = headers["content-disposition"];
        const sourceOrigin = originOfUrl(download.url());
        const filename = download.suggestedFilename();
        if (
          mimeType === undefined ||
          disposition === undefined ||
          sourceOrigin === "null" ||
          filename.length === 0
        ) {
          throw new TypeError("download metadata unavailable before exposure");
        }
        const metadata: DownloadMetadata = Object.freeze({
          sourceOrigin,
          mimeType,
          filename,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          disposition,
          bytes: bytes.length,
        });
        session.recordPostAction("DOWNLOAD", { ...metadata });
        return metadata;
      } finally {
        await download.delete();
      }
    },
    locator,
    rawPage: (reason) => session.unsafe.rawPage(reason) as Page,
  };
}

function validateUploadFiles(files: unknown, options: unknown): readonly PlaywrightUploadFile[] {
  if (
    !isRecord(options) ||
    options["taskNecessary"] !== true ||
    (options["provenance"] !== "application" && options["provenance"] !== "user") ||
    (options["sensitivity"] !== "public" && options["sensitivity"] !== "sensitive")
  ) {
    throw new TypeError("uploads require trusted provenance, sensitivity, and task necessity");
  }
  if (!Array.isArray(files) || files.length === 0 || files.length > 20)
    throw new TypeError("upload requires 1 to 20 in-memory files");
  return Object.freeze(
    files.map((file) => {
      if (
        !isRecord(file) ||
        typeof file["name"] !== "string" ||
        file["name"].length === 0 ||
        file["name"].length > 256 ||
        !Buffer.isBuffer(file["buffer"]) ||
        (file["mimeType"] !== undefined &&
          (typeof file["mimeType"] !== "string" || file["mimeType"].length > 256))
      ) {
        throw new TypeError(
          "uploads require bounded in-memory file payloads; paths are not allowed",
        );
      }
      return Object.freeze({
        name: file["name"],
        buffer: Buffer.from(file["buffer"]),
        ...(file["mimeType"] !== undefined ? { mimeType: file["mimeType"] } : {}),
      });
    }),
  );
}

async function canonicalAction(
  page: Page,
  operation: PlaywrightOperation,
  observation: PageObservation,
  data: unknown,
): Promise<CanonicalAction> {
  const origin = observation.origin;
  switch (operation.method) {
    case "helper":
      if (operation.helper === undefined)
        throw new TypeError("helper operation lacks registration");
      return {
        type: "EXECUTE_SCRIPT",
        target: { origin },
        data: { helper: { name: operation.helper.name, sha256: operation.helper.sha256 } },
        instructionProvenance: { trust: "application" },
        raw: operation,
      };
    case "goto": {
      const destination = operation.arguments[0];
      if (destination === undefined) throw new TypeError("Playwright goto lacks a destination");
      return {
        type: "NAVIGATE",
        navigationOrigin: "direct",
        destination,
        target: { origin },
        instructionProvenance: { trust: "application" },
        raw: operation,
      };
    }
    case "fill":
      return targetAction("FILL", operation, origin, data);
    case "type":
      return targetAction("TYPE", operation, origin, data);
    case "press":
      return operation.arguments[0] === "Enter"
        ? submitOrClickAction(page, operation, origin, data)
        : targetAction("TYPE", operation, origin, data);
    case "setInputFiles":
      return uploadAction(page, operation, origin, data);
    case "download":
      return downloadAction(page, operation, origin);
    default:
      return submitOrClickAction(page, operation, origin, data);
  }
}

function targetAction(
  type: "CLICK" | "TYPE" | "FILL" | "UPLOAD",
  operation: PlaywrightOperation,
  origin: string,
  data: unknown,
): CanonicalAction {
  if (operation.selector === undefined)
    throw new TypeError("Playwright operation lacks a target selector");
  return {
    type,
    target: { element: operation.selector, origin },
    data: data ?? operation.arguments,
    instructionProvenance: { trust: "application" },
    raw: operation,
  };
}

async function submitOrClickAction(
  page: Page,
  operation: PlaywrightOperation,
  origin: string,
  data: unknown,
): Promise<CanonicalAction> {
  const selector = requiredSelector(operation);
  const form = await formDetails(page, selector);
  const entersForm = operation.method === "press" && operation.arguments[0] === "Enter";
  if (form !== undefined && (form.submitControl || entersForm)) {
    return {
      type: "SUBMIT",
      target: { element: selector, origin },
      destination: form.action,
      data: {
        method: form.method,
        fields: form.fields,
        ...(data !== undefined ? { data } : {}),
      },
      instructionProvenance: { trust: "application" },
      raw: operation,
    };
  }
  return targetAction("CLICK", operation, origin, data);
}

async function uploadAction(
  page: Page,
  operation: PlaywrightOperation,
  origin: string,
  data: unknown,
): Promise<CanonicalAction> {
  const selector = requiredSelector(operation);
  const form = await formDetails(page, selector);
  if (form === undefined) {
    throw new TypeError("guarded uploads require an associated form destination");
  }
  return {
    type: "UPLOAD",
    target: { element: selector, origin },
    destination: form.action,
    data,
    instructionProvenance: { trust: "application" },
    raw: operation,
  };
}

async function downloadAction(
  page: Page,
  operation: PlaywrightOperation,
  origin: string,
): Promise<CanonicalAction> {
  const selector = requiredSelector(operation);
  const href = await page.locator(selector).getAttribute("href");
  return {
    type: "DOWNLOAD",
    target: { element: selector, origin },
    ...(href !== null ? { destination: absoluteUrl(page.url(), href) } : {}),
    instructionProvenance: { trust: "application" },
    raw: operation,
  };
}

interface FormDetails {
  readonly action: string;
  readonly method: string;
  readonly fields: readonly { readonly name: string; readonly type: string }[];
  readonly submitControl: boolean;
}

async function formDetails(page: Page, selector: string): Promise<FormDetails | undefined> {
  const locator = page.locator(selector);
  if ((await locator.count()) !== 1) return undefined;
  return locator.evaluate((node) => {
    const element = node as unknown as {
      readonly tagName: string;
      getAttribute(name: string): string | null;
      closest(selector: string): {
        readonly action: string;
        readonly method: string;
        readonly elements: ArrayLike<{ readonly name?: string; readonly type?: string }>;
      } | null;
    };
    const form = element.closest("form");
    if (form === null) return undefined;
    const type = element.getAttribute("type")?.toLowerCase();
    const submitControl =
      (element.tagName === "BUTTON" && (type === undefined || type === "submit")) ||
      type === "submit";
    return {
      action: form.action,
      method: (form.method || "get").toLowerCase(),
      fields: Array.from(form.elements)
        .slice(0, 32)
        .map((field) => ({
          name: (field.name ?? "").slice(0, 128),
          type: (field.type ?? "").slice(0, 64),
        })),
      submitControl,
    };
  });
}

function requiredSelector(operation: PlaywrightOperation): string {
  if (operation.selector === undefined || operation.selector.length === 0) {
    throw new TypeError("playwright operation lacks a selector");
  }
  return operation.selector;
}

/** Resolve the exact state which is compared again by the adapter on execution. */
export async function currentState(
  page: Page,
  observation: PageObservation,
  operation: PlaywrightOperation,
  policyHash: string,
): Promise<IntentStateSnapshot> {
  if (
    observation.pageId === undefined ||
    observation.contextId === undefined ||
    observation.revision === undefined
  ) {
    throw new TypeError("Playwright observation lacks adapter identity for state binding");
  }
  const base = {
    observation: {
      browserContextId: observation.contextId,
      pageId: observation.pageId,
      revision: observation.revision,
    },
    policyHash,
    operationHash: fingerprint(JSON.stringify(operation)),
  };
  if (operation.method === "helper") {
    return {
      ...base,
      target: { origin: observation.origin },
      frameOrigin: observation.origin,
      securityAttributes: Object.freeze({}),
      visibility: "not_applicable",
    };
  }
  if (operation.selector === undefined) {
    const destination = operation.arguments[0];
    if (destination === undefined) throw new TypeError("Playwright goto lacks a destination");
    return {
      ...base,
      target: { origin: observation.origin },
      frameOrigin: observation.origin,
      destination,
      securityAttributes: Object.freeze({}),
      visibility: "not_applicable",
    };
  }
  const locator = page.locator(operation.selector);
  if ((await locator.count()) !== 1) {
    throw new TypeError("Playwright target is missing or ambiguous");
  }
  const details = (await locator.evaluate((node) => {
    const element = node as unknown as {
      getAttribute(name: string): string | null;
      getBoundingClientRect(): { readonly width: number; readonly height: number };
      readonly disabled?: boolean;
      closest(selector: string): { getAttribute(name: string): string | null } | null;
    };
    const style = (
      globalThis as unknown as {
        getComputedStyle(value: unknown): {
          readonly display: string;
          readonly visibility: string;
          readonly opacity: string;
        };
      }
    ).getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    const attributes: Record<string, string> = {};
    for (const name of [
      "href",
      "action",
      "method",
      "target",
      "type",
      "name",
      "role",
      "aria-disabled",
      "disabled",
      "readonly",
      "formaction",
    ]) {
      const value = element.getAttribute(name);
      if (value !== null) attributes[name] = value;
    }
    const form = element.closest("form");
    return {
      attributes,
      visible: !(
        style.display === "none" ||
        style.visibility === "hidden" ||
        Number(style.opacity) === 0 ||
        rect.width === 0 ||
        rect.height === 0
      ),
      enabled: element.disabled !== true,
      formAction: form?.getAttribute("action") ?? null,
    };
  })) as {
    readonly attributes: Readonly<Record<string, string>>;
    readonly visible: boolean;
    readonly enabled: boolean;
    readonly formAction: string | null;
  };
  const attributes = Object.freeze({
    ...details.attributes,
    enabled: String(details.enabled),
  });
  const href = details.attributes["href"];
  const formAction =
    details.attributes["formaction"] ??
    details.attributes["action"] ??
    details.formAction ??
    undefined;
  return {
    ...base,
    target: {
      selector: operation.selector,
      element: operation.selector,
      origin: observation.origin,
    },
    frameOrigin: observation.origin,
    ...(href !== undefined ? { destination: absoluteUrl(page.url(), href) } : {}),
    ...(formAction !== undefined ? { formAction: absoluteUrl(page.url(), formAction) } : {}),
    securityAttributes: attributes,
    visibility: details.visible ? "visible" : "hidden",
  };
}

function absoluteUrl(base: string, value: string): string {
  try {
    return new URL(value, base).toString();
  } catch {
    return value;
  }
}

function originOfUrl(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return value;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function waitForDownload(page: Page): Promise<Download> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      page.off("download", onDownload);
      reject(new Error("download event did not arrive before metadata timeout"));
    }, 5_000);
    const onDownload = (download: Download): void => {
      clearTimeout(timeout);
      resolve(download);
    };
    page.once("download", onDownload);
  });
}
