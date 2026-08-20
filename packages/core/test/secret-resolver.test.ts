import { describe, expect, it, vi } from "vitest";
import {
  compileTaskContract,
  createScopedSecretResolver,
  mintHandle,
  OpenAgentFence,
  provenanced,
  serializeHandle,
  validateTaskContract,
  type ActionIntent,
  type Authorized,
  type ResolverSessionState,
  type SecretResolutionAudit,
  type SinkBinding,
  type SinkTarget,
  type SecretHandle,
  type VaultAdapter,
} from "../src/index.js";
import { mintAuthorizedAction } from "../src/action/authorized.js";
import { fakeAdapter } from "./helpers.js";

const ORIGIN = "https://login.example";
const TARGET: SinkTarget = { origin: ORIGIN, fieldType: "password", selector: "#password" };
const BINDING: SinkBinding = {
  name: "login",
  kind: "CREDENTIAL",
  origins: [ORIGIN],
  fieldTypes: ["password"],
  selector: "#password",
};

function envelope() {
  const contract = validateTaskContract({
    task: "sign in",
    capabilities: { credentials: true },
    secrets: [
      {
        name: "login",
        kind: "CREDENTIAL",
        origins: [ORIGIN],
        fieldTypes: ["password"],
        selector: "#password",
      },
    ],
  });
  if (!contract.ok) throw new Error(contract.errors.join(","));
  return compileTaskContract(contract.value);
}

function authorization(
  handle = mintHandle("CREDENTIAL", "login"),
  formAction?: string,
): {
  readonly authorized: Authorized;
  readonly handle: typeof handle;
} {
  const action = {
    type: "FILL" as const,
    target: { element: "#password", origin: ORIGIN },
    data: provenanced(serializeHandle(handle), { trust: "application" }),
    instructionProvenance: { trust: "application" as const },
  };
  const intent: ActionIntent = {
    intentId: "intent-secret",
    actionId: "action-secret",
    action,
    observation: { browserContextId: "ctx", pageId: "page", revision: 1 },
    target: { selector: "#password", element: "#password", origin: ORIGIN },
    ...(formAction === undefined ? {} : { formAction }),
    securityAttributes: { type: "password" },
    visibility: "visible",
    policyHash: "policy",
    operationHash: "operation",
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
  };
  return {
    authorized: mintAuthorizedAction({
      action,
      intent,
      operationHash: "operation",
      policyHash: "policy",
      decisionId: "decision",
      traceId: "trace",
    }),
    handle,
  };
}

function normalState(overrides: Partial<ResolverSessionState> = {}): ResolverSessionState {
  return {
    riskState: "NORMAL",
    policyHash: "policy",
    sessionActive: true,
    actionStateValid: true,
    ...overrides,
  };
}

describe("sink-bound secret resolution", () => {
  it("resolves one exact bound handle, commits the sink, and rejects scope reuse", async () => {
    const { authorized, handle } = authorization();
    const approved = new Set<string>();
    const audits: SecretResolutionAudit[] = [];
    const lookup = vi.fn(async () => "synthetic-vault-value");
    const resolver = createScopedSecretResolver({
      authorized,
      bindings: [BINDING],
      envelope: envelope(),
      lookup: { lookup },
      currentState: () => normalState(),
      wasApproved: (key) => approved.has(key),
      approve: (key) => approved.add(key),
      audit: (audit) => audits.push(audit),
    });

    await expect(resolver.resolveForSink(handle, TARGET)).resolves.toBe("synthetic-vault-value");
    expect(approved.size).toBe(0);
    resolver.commit();
    expect(approved.size).toBe(1);
    resolver.revoke();
    await expect(resolver.resolveForSink(handle, TARGET)).resolves.toBeNull();
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(audits)).not.toContain("synthetic-vault-value");
  });

  it.each([
    ["origin", { ...TARGET, origin: "https://evil.example" }, normalState()],
    ["field", { ...TARGET, fieldType: "text" }, normalState()],
    ["selector", { ...TARGET, selector: "#other" }, normalState()],
    ["read-only", TARGET, normalState({ riskState: "READ_ONLY" })],
    ["quarantined", TARGET, normalState({ riskState: "QUARANTINED" })],
    ["ended", TARGET, normalState({ sessionActive: false })],
    ["stale", TARGET, normalState({ actionStateValid: false })],
    ["policy", TARGET, normalState({ policyHash: "changed" })],
  ])("denies %s mismatch before vault access", async (_name, target, state) => {
    const { authorized, handle } = authorization();
    const lookup = vi.fn(async () => "must-not-be-read");
    const resolver = createScopedSecretResolver({
      authorized,
      bindings: [BINDING],
      envelope: envelope(),
      lookup: { lookup },
      currentState: () => state,
      wasApproved: () => false,
      approve: () => undefined,
    });
    await expect(resolver.resolveForSink(handle, target)).resolves.toBeNull();
    expect(lookup).not.toHaveBeenCalled();
  });

  it("requires a previously committed exact sink in RESTRICTED and honors deny_all", async () => {
    const { authorized, handle } = authorization();
    const approved = new Set<string>();
    const lookup = vi.fn(async () => "synthetic-restricted-value");
    const make = (
      state: ResolverSessionState,
      restrictedMode: "keep_approved_sinks" | "deny_all",
    ) =>
      createScopedSecretResolver({
        authorized,
        bindings: [BINDING],
        envelope: envelope(),
        lookup: { lookup },
        currentState: () => state,
        restrictedMode,
        wasApproved: (key) => approved.has(key),
        approve: (key) => approved.add(key),
      });

    const firstRestricted = make(normalState({ riskState: "RESTRICTED" }), "keep_approved_sinks");
    await expect(firstRestricted.resolveForSink(handle, TARGET)).resolves.toBeNull();
    expect(lookup).not.toHaveBeenCalled();

    const normal = make(normalState(), "keep_approved_sinks");
    await expect(normal.resolveForSink(handle, TARGET)).resolves.toBe("synthetic-restricted-value");
    normal.commit();
    normal.revoke();

    const restricted = make(normalState({ riskState: "RESTRICTED" }), "keep_approved_sinks");
    await expect(restricted.resolveForSink(handle, TARGET)).resolves.toBe(
      "synthetic-restricted-value",
    );
    const denyAll = make(normalState({ riskState: "RESTRICTED" }), "deny_all");
    await expect(denyAll.resolveForSink(handle, TARGET)).resolves.toBeNull();
  });

  it("rejects a validly shaped handle not present in the exact authorized operation", async () => {
    const { authorized } = authorization();
    const other = mintHandle("CREDENTIAL", "login");
    const lookup = vi.fn(async () => "must-not-be-read");
    const resolver = createScopedSecretResolver({
      authorized,
      bindings: [BINDING],
      envelope: envelope(),
      lookup: { lookup },
      currentState: () => normalState(),
      wasApproved: () => false,
      approve: () => undefined,
    });
    await expect(resolver.resolveForSink(other, TARGET)).resolves.toBeNull();
    expect(lookup).not.toHaveBeenCalled();
  });

  it("denies a mutated or unbound form action before lookup", async () => {
    const evilForm = "https://evil.example/collect";
    const { authorized, handle } = authorization(undefined, evilForm);
    const lookup = vi.fn(async () => "must-not-be-read");
    const resolver = createScopedSecretResolver({
      authorized,
      bindings: [BINDING],
      envelope: envelope(),
      lookup: { lookup },
      currentState: () => normalState(),
      wasApproved: () => false,
      approve: () => undefined,
    });
    await expect(
      resolver.resolveForSink(handle, { ...TARGET, formAction: evilForm }),
    ).resolves.toBeNull();
    expect(lookup).not.toHaveBeenCalled();
  });

  it("creates and revokes the resolver only inside session-issued exact execution", async () => {
    let stored: { handle: SecretHandle; value: string } | undefined;
    const execution = { handle: undefined as SecretHandle | undefined };
    const lookup = vi.fn(async (handle: SecretHandle) =>
      stored !== undefined && serializeHandle(stored.handle) === serializeHandle(handle)
        ? stored.value
        : null,
    );
    const vault: VaultAdapter = {
      openSession: () => ({
        store: async (name, value, kind = "SECRET") => {
          const handle = mintHandle(kind, name);
          stored = { handle, value };
          return handle;
        },
        createExecutorLookup: () => ({ lookup }),
        invalidateSession: async () => {
          stored = undefined;
        },
      }),
    };
    const adapter = fakeAdapter({
      executeAuthorized: async (_authorized, resolver) => {
        if (execution.handle === undefined) throw new Error("missing test handle");
        return resolver.resolveForSink(execution.handle, TARGET);
      },
    });
    const firewall = new OpenAgentFence({ adapter, vault });
    const session = firewall.start({
      task: "sign in",
      capabilities: { credentials: true },
      secrets: [
        {
          name: "login",
          kind: "CREDENTIAL",
          origins: [ORIGIN],
          fieldTypes: ["password"],
          selector: "#password",
        },
      ],
    });
    execution.handle = await session.registerSecret(
      "login",
      "synthetic-session-secret",
      "CREDENTIAL",
    );
    const action = {
      type: "FILL" as const,
      target: { element: "#password", origin: ORIGIN },
      data: provenanced(serializeHandle(execution.handle), { trust: "application" }),
      instructionProvenance: { trust: "application" as const },
    };
    const intent: ActionIntent = {
      intentId: "session-intent",
      actionId: "session-action",
      action,
      observation: { browserContextId: "ctx", pageId: "page", revision: 1 },
      target: { selector: "#password", element: "#password", origin: ORIGIN },
      securityAttributes: { type: "password" },
      visibility: "visible",
      policyHash: session.policyEngine.policyHash,
      operationHash: "session-operation",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    };
    const bound = await session.authorizeBound(action, intent);
    if (bound.authorized === undefined) throw new Error("expected authorization");
    const result = await session.executeAuthorized(bound.authorized);
    expect(result).toBe("[REDACTED]");
    expect(lookup).toHaveBeenCalledTimes(1);
    await expect(session.executeAuthorized(bound.authorized)).rejects.toThrow("already used");
    const trace = await session.end();
    const resolution = trace.events.find((event) => event.kind === "secret_resolution");
    expect(resolution?.data["outcome"]).toBe("allowed");
    expect(JSON.stringify(trace)).not.toContain("synthetic-session-secret");
  });
});
