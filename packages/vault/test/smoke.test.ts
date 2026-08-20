import { describe, expect, it } from "vitest";
import { PACKAGE_NAME, inMemoryVault } from "../src/index.js";

describe("@openagentfence/vault", () => {
  it("exposes its package name", () => {
    expect(PACKAGE_NAME).toBe("@openagentfence/vault");
  });
});

describe("inMemoryVault", () => {
  it("issues opaque unique handles and only resolves through a session executor capability", async () => {
    const vault = inMemoryVault();
    const session = vault.openSession("0123456789abcdef");
    const first = await session.store("github_token", "synthetic-secret-value");
    const second = await session.store("github_token", "synthetic-secret-value");
    expect(first.id).toMatch(/^[a-f0-9]{32}$/);
    expect(first.id).not.toBe(second.id);
    expect(JSON.stringify(first)).not.toContain("synthetic-secret-value");
    expect(await session.createExecutorLookup().lookup(first)).toBe("synthetic-secret-value");
  });

  it("denies stale, cross-session, expired, cancelled, and bounded registrations", async () => {
    let clock = 0;
    const vault = inMemoryVault({
      maxEntriesPerSession: 1,
      maxValueBytes: 8,
      ttlMs: 10,
      now: () => clock,
    });
    const one = vault.openSession("0123456789abcdef");
    const two = vault.openSession("fedcba9876543210");
    const handle = await one.store("key", "value");
    expect(await two.createExecutorLookup().lookup(handle)).toBeNull();
    await expect(one.store("second", "value")).rejects.toThrow("handle limit");
    await expect(two.store("oversized", "123456789")).rejects.toThrow("vault limit");
    clock = 11;
    expect(await one.createExecutorLookup().lookup(handle)).toBeNull();
    const fresh = await two.store("key", "value");
    const controller = new AbortController();
    controller.abort();
    expect(await two.createExecutorLookup().lookup(fresh, controller.signal)).toBeNull();
    await two.invalidateSession();
    expect(await two.createExecutorLookup().lookup(fresh)).toBeNull();
    await expect(two.store("again", "value")).rejects.toThrow("no longer active");
  });

  it("rejects invalid limits and reuses a live session view", () => {
    expect(() => inMemoryVault({ maxEntriesPerSession: 0 })).toThrow("maxEntriesPerSession");
    expect(() => inMemoryVault({ maxValueBytes: 0 })).toThrow("maxValueBytes");
    expect(() => inMemoryVault({ ttlMs: 0 })).toThrow("ttlMs");
    const vault = inMemoryVault();
    expect(vault.openSession("0123456789abcdef")).toBe(vault.openSession("0123456789abcdef"));
    expect(() => vault.openSession("not-a-session")).toThrow("invalid session id");
  });
});
