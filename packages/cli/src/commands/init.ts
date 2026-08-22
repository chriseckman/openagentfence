import { parsePolicyDocumentSource, validatePolicy } from "@openagentfence/policy";
import {
  CLI_EXIT,
  type CliFileSystem,
  type CliIo,
  isBoundedPath,
  nodeFileSystem,
} from "./common.js";

export const SECURE_DEFAULT_POLICY = `version: 1
defaults:
  unknown_action: block
  scanner_failure:
    low_risk: warn
    high_risk: block
navigation:
  mode: same-site
  block_private_networks: true
actions:
  upload: deny
  delete: approval
  purchase: approval
  message: approval
  execute_script: deny
  download: deny
  authenticate: approval
  publish: approval
  change_setting: approval
secrets:
  resolution: executor_only
injection:
  high_confidence: restricted_mode
  critical: quarantine
`;

export interface InitDependencies {
  readonly files?: CliFileSystem;
}

export async function runInitCommand(
  args: readonly string[],
  io: CliIo,
  dependencies: InitDependencies = {},
): Promise<number> {
  const parsed = parseInitArgs(args);
  if (parsed === null) {
    io.stderr("usage: openagentfence init [--force] [--path <openagentfence.yml>]\n");
    return CLI_EXIT.usage;
  }
  try {
    const policy = parsePolicyDocumentSource(SECURE_DEFAULT_POLICY, "openagentfence.yml");
    if (validatePolicy(policy).errors.length > 0)
      throw new TypeError("secure default policy invalid");
    await (dependencies.files ?? nodeFileSystem).writeFile(parsed.path, SECURE_DEFAULT_POLICY, {
      flag: parsed.force ? "w" : "wx",
    });
    io.stdout("secure default policy written\n");
    return CLI_EXIT.success;
  } catch {
    io.stderr(
      parsed.force
        ? "could not write policy file\n"
        : "policy file already exists or could not be written\n",
    );
    return CLI_EXIT.failure;
  }
}

interface ParsedInitArgs {
  readonly force: boolean;
  readonly path: string;
}

function parseInitArgs(args: readonly string[]): ParsedInitArgs | null {
  let force = false;
  let path = "openagentfence.yml";
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--force" && !force) {
      force = true;
      continue;
    }
    if (argument === "--path") {
      const value = args[index + 1];
      if (value === undefined || !isBoundedPath(value)) return null;
      path = value;
      index += 1;
      continue;
    }
    return null;
  }
  return Object.freeze({ force, path });
}
