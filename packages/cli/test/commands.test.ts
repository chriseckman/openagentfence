import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { loadPolicyDocument, validatePolicy } from "@openagentfence/policy";
import { afterEach, describe, expect, it } from "vitest";
import { runDoctorCommand } from "../src/commands/doctor.js";
import { runExplainCommand } from "../src/commands/explain.js";
import { runInitCommand, SECURE_DEFAULT_POLICY } from "../src/commands/init.js";
import { runPolicyValidateCommand } from "../src/commands/policy.js";

const workspaces: string[] = [];
const fixtures = resolve("test/fixtures/traces");

afterEach(async () => {
  await Promise.all(workspaces.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("P0 secure CLI commands", () => {
  it("initializes a validated explicit secure policy without provider configuration or accidental overwrite", async () => {
    const directory = await workspace();
    const path = join(directory, "openagentfence.yml");
    const output = capture();
    await expect(runInitCommand(["--path", path], output.io)).resolves.toBe(0);
    expect(await readFile(path, "utf8")).toBe(SECURE_DEFAULT_POLICY);
    expect(validatePolicy(await loadPolicyDocument(path)).errors).toEqual([]);
    expect(await readFile(path, "utf8")).not.toMatch(/provider|credential|api[_-]?key/iu);

    const sentinel = "oaf_synthetic_secret_must_not_escape";
    await writeFile(path, sentinel, "utf8");
    const rejected = capture();
    await expect(runInitCommand(["--path", path], rejected.io)).resolves.toBe(1);
    expect(await readFile(path, "utf8")).toBe(sentinel);
    expect(`${rejected.stdout.join("")}${rejected.stderr.join("")}`).not.toContain(sentinel);
    await expect(runInitCommand(["--force", "--path", path], capture().io)).resolves.toBe(0);
    expect(await readFile(path, "utf8")).toBe(SECURE_DEFAULT_POLICY);
  });

  it("reports Playwright capability gaps truthfully and makes no provider call without explicit opt-in", async () => {
    let calls = 0;
    const defaultOutput = capture();
    await expect(
      runDoctorCommand(["--json"], defaultOutput.io, {
        providerChecker: {
          check: async () => {
            calls += 1;
            return "reachable";
          },
        },
        nodeVersion: "v24.19.0",
        platform: "fixture-os",
      }),
    ).resolves.toBe(0);
    expect(calls).toBe(0);
    const report = JSON.parse(defaultOutput.stdout.join("")) as {
      playwright: { capabilities: { network: Record<string, string> }; gaps: string[] };
      stagehand: { status: string };
      providerConnectivity: { status: string };
    };
    expect(report.playwright.capabilities.network).toMatchObject({
      navigation: "observed_only",
      fetch: "observed_only",
    });
    expect(report.playwright.gaps).toContain("redirect:unavailable");
    expect(report.stagehand.status).toBe("not_inspected");
    expect(report.providerConnectivity.status).toBe("not_checked");

    const routed = capture();
    await expect(
      runDoctorCommand(
        ["--json", "--route-requests", "--check-provider", "https://fixture.invalid"],
        routed.io,
        {
          providerChecker: {
            check: async () => {
              calls += 1;
              return "reachable";
            },
          },
        },
      ),
    ).resolves.toBe(0);
    expect(calls).toBe(1);
    expect(JSON.parse(routed.stdout.join("")).playwright.capabilities.network).toMatchObject({
      navigation: "enforced",
      fetch: "enforced",
      redirect: "observed_only",
    });

    const secret = "oaf_synthetic_secret_must_not_escape";
    const unavailable = capture();
    await expect(
      runDoctorCommand(["--check-provider", `https://${secret}@fixture.invalid`], unavailable.io, {
        providerChecker: {
          check: async () => {
            throw new Error(secret);
          },
        },
      }),
    ).resolves.toBe(1);
    expect(`${unavailable.stdout.join("")}${unavailable.stderr.join("")}`).not.toContain(secret);
  });

  it("renders only a closed redacted decision projection and rejects leaky input", async () => {
    const directory = await workspace();
    const valid = join(directory, "vertical.json");
    const leaky = join(directory, "leaky.json");
    await cp(join(fixtures, "vertical-slice.redacted.json"), valid);
    await cp(join(fixtures, "leaky-sentinel.json"), leaky);
    const output = capture();
    await expect(runExplainCommand([valid, "--json"], output.io)).resolves.toBe(0);
    const projection = JSON.parse(output.stdout.join("")) as {
      decisions: Array<{ verdict?: string; reasons?: string[] }>;
    };
    expect(projection.decisions).toContainEqual(
      expect.objectContaining({
        verdict: "BLOCK",
        reasons: ["navigation_instruction_originated_from_untrusted_dom", "session_restricted"],
      }),
    );
    const text = capture();
    await expect(runExplainCommand([valid], text.io)).resolves.toBe(0);
    expect(text.stdout.join("")).toMatchInlineSnapshot(`
      "trace schema: 1.6.0
      2026-08-21T00:00:01.000Z finding
      2026-08-21T00:00:01.000Z risk_change
      2026-08-21T00:00:03.000Z policy_decision BLOCK navigation_instruction_originated_from_untrusted_dom,session_restricted
      "
    `);
    const failed = capture();
    await expect(runExplainCommand([leaky], failed.io)).resolves.toBe(1);
    expect(`${failed.stdout.join("")}${failed.stderr.join("")}`).not.toContain(
      "oaf_synthetic_secret_must_not_render",
    );
  });

  it("validates policy files through the strict parser with stable, source-free errors", async () => {
    const directory = await workspace();
    const valid = join(directory, "openagentfence.yml");
    const invalid = join(directory, "invalid.yml");
    await writeFile(valid, SECURE_DEFAULT_POLICY, "utf8");
    await writeFile(
      invalid,
      "version: 1\nunknown_provider_key: oaf_synthetic_secret_must_not_render\n",
      "utf8",
    );
    await expect(runPolicyValidateCommand([valid], capture().io)).resolves.toBe(0);
    const failure = capture();
    await expect(runPolicyValidateCommand([invalid], failure.io)).resolves.toBe(1);
    expect(failure.stderr.join("")).toContain("policy.unknown_provider_key");
    expect(failure.stderr.join("")).not.toContain("oaf_synthetic_secret_must_not_render");

    const warning = join(directory, "warning.yml");
    await writeFile(warning, "version: 1\nnavigation:\n  block_private_networks: false\n", "utf8");
    const warningOutput = capture();
    await expect(runPolicyValidateCommand([warning], warningOutput.io)).resolves.toBe(0);
    expect(warningOutput.stdout.join("")).toContain("warning: navigation.block_private_networks");
  });
});

function capture(): {
  readonly stdout: string[];
  readonly stderr: string[];
  readonly io: {
    readonly stdout: (value: string) => void;
    readonly stderr: (value: string) => void;
  };
} {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    io: { stdout: (value) => stdout.push(value), stderr: (value) => stderr.push(value) },
  };
}

async function workspace(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "openagentfence-cli-"));
  workspaces.push(directory);
  return directory;
}
