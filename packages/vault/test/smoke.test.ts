import { describe, expect, it } from "vitest";
import { createVaultExecutorAccess } from "@openagentfence/core/internal";
import { PACKAGE_NAME, inMemoryVault } from "../src/index.js";

describe("@openagentfence/vault", () => {
  it("exposes its package name", () => {
    expect(PACKAGE_NAME).toBe("@openagentfence/vault");
  });
});

describe("inMemoryVault", () => {
  it("issues opaque unique handles and only resolves through a session executor capability", async () => {
    const vault = inMemoryVault();
    const access = createVaultExecutorAccess();
    const session = vault.openSession("0123456789abcdef", access);
    const first = await session.store("github_token", "synthetic-secret-value");
    const second = await session.store("github_token", "synthetic-secret-value");
    expect(first.id).toMatch(/^[a-f0-9]{32}$/);
    expect(first.id).not.toBe(second.id);
    expect(JSON.stringify(first)).not.toContain("synthetic-secret-value");
    expect(await session.createExecutorLookup(access).lookup(first)).toBe("synthetic-secret-value");
  });

  it("denies stale, cross-session, expired, cancelled, and bounded registrations", async () => {
    let clock = 0;
    const vault = inMemoryVault({
      maxEntriesPerSession: 1,
      maxValueBytes: 8,
      ttlMs: 10,
      now: () => clock,
    });
    const access = createVaultExecutorAccess();
    const one = vault.openSession("0123456789abcdef", access);
    const two = vault.openSession("fedcba9876543210", access);
    const handle = await one.store("key", "value");
    expect(await two.createExecutorLookup(access).lookup(handle)).toBeNull();
    await expect(one.store("second", "value")).rejects.toThrow("handle limit");
    await expect(two.store("oversized", "123456789")).rejects.toThrow("vault limit");
    clock = 11;
    expect(await one.createExecutorLookup(access).lookup(handle)).toBeNull();
    const fresh = await two.store("key", "value");
    const controller = new AbortController();
    controller.abort();
    expect(await two.createExecutorLookup(access).lookup(fresh, controller.signal)).toBeNull();
    await two.invalidateSession();
    expect(await two.createExecutorLookup(access).lookup(fresh)).toBeNull();
    await expect(two.store("again", "value")).rejects.toThrow("no longer active");
  });

  it("rejects invalid limits and reuses a live session view", () => {
    expect(() => inMemoryVault({ maxEntriesPerSession: 0 })).toThrow("maxEntriesPerSession");
    expect(() => inMemoryVault({ maxValueBytes: 0 })).toThrow("maxValueBytes");
    expect(() => inMemoryVault({ ttlMs: 0 })).toThrow("ttlMs");
    const vault = inMemoryVault();
    const access = createVaultExecutorAccess();
    expect(vault.openSession("0123456789abcdef", access)).toBe(
      vault.openSession("0123456789abcdef", access),
    );
    expect(() => vault.openSession("not-a-session", access)).toThrow("invalid session id");
    expect(() => vault.openSession("1111111111111111", {} as never)).toThrow(
      "vault session access denied",
    );
    const session = vault.openSession("2222222222222222", access);
    expect(() => session.createExecutorLookup({} as never)).toThrow("vault executor access denied");
  });
});
