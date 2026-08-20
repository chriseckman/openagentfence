import type { IntentStateSnapshot, SecretResolver } from "@openagentfence/core";
import { describe, expect, it, vi } from "vitest";
import {
  assertSecretOperationSupported,
  executorArgument,
  withExecutorArgument,
} from "../src/execute-secrets.js";
import type { PlaywrightOperation } from "../src/wrap.js";

const HANDLE = `<CREDENTIAL:login-password:${"a".repeat(32)}>`;

const state = (
  attributes: Readonly<Record<string, string>> = {
    tagName: "input",
    type: "password",
  },
): IntentStateSnapshot => ({
  observation: { browserContextId: "context", pageId: "page", revision: 1 },
  target: { selector: "#password", element: "#password", origin: "https://auth.example" },
  formAction: "https://auth.example/session",
  securityAttributes: attributes,
  visibility: "visible",
  policyHash: "policy",
  operationHash: "operation",
});

const operation = (method: PlaywrightOperation["method"], value = HANDLE): PlaywrightOperation => ({
  adapter: "playwright",
  method,
  selector: "#password",
  arguments: [value],
});

describe("executor-private Playwright secret substitution", () => {
  it.each(["fill", "type", "selectOption"] as const)(
    "resolves a whole handle for a live %s sink",
    async (method) => {
      const resolveForSink = vi.fn(async () => "synthetic-value");
      const result = await executorArgument(operation(method), state(), { resolveForSink });
      expect(result).toEqual({ value: "synthetic-value", sensitive: true });
      expect(resolveForSink).toHaveBeenCalledWith(
        expect.objectContaining({ name: "login-password" }),
        {
          origin: "https://auth.example",
          fieldType: "password",
          selector: "#password",
          formAction: "https://auth.example/session",
        },
      );
    },
  );

  it("passes a non-secret argument through without resolver access", async () => {
    const resolveForSink = vi.fn();
    const resolver: SecretResolver = { resolveForSink };
    await expect(executorArgument(operation("fill", "public"), state(), resolver)).resolves.toEqual(
      { value: "public", sensitive: false },
    );
    expect(resolveForSink).not.toHaveBeenCalled();
  });

  it("rejects embedded, unsupported, and metadata-free handles before browser execution", async () => {
    const resolveForSink = vi.fn();
    const resolver: SecretResolver = { resolveForSink };
    await expect(
      executorArgument(operation("fill", `prefix-${HANDLE}`), state(), resolver),
    ).rejects.toThrow("whole-value");
    expect(() => assertSecretOperationSupported(operation("goto"))).toThrow("not supported");
    await expect(executorArgument(operation("fill"), state({}), resolver)).rejects.toThrow(
      "metadata",
    );
    expect(resolveForSink).not.toHaveBeenCalled();
  });

  it("replaces a post-resolution framework error with a value-free error", async () => {
    const sentinel = "synthetic-value-never-returned";
    const resolver: SecretResolver = { resolveForSink: async () => sentinel };
    const failure = await withExecutorArgument(
      operation("fill"),
      state(),
      resolver,
      async (value) => {
        throw new Error(`framework reflected ${value}`);
      },
    ).catch((error: unknown) => error);
    expect(String(failure)).not.toContain(sentinel);
    expect(String(failure)).toContain("secret sink execution failed");
  });
});
