import {
  parsePolicyDocumentSource,
  PolicyDocumentError,
  validatePolicy,
} from "@openagentfence/policy";
import {
  CLI_EXIT,
  isBoundedFileSize,
  isBoundedPath,
  MAX_CLI_INPUT_BYTES,
  nodeFileSystem,
  type CliFileSystem,
  type CliIo,
} from "./common.js";

export interface PolicyValidateDependencies {
  readonly files?: CliFileSystem;
}

export async function runPolicyValidateCommand(
  args: readonly string[],
  io: CliIo,
  dependencies: PolicyValidateDependencies = {},
): Promise<number> {
  if (args.length > 1 || (args[0] !== undefined && !isBoundedPath(args[0]))) {
    io.stderr("usage: openagentfence policy validate [openagentfence.yml]\n");
    return CLI_EXIT.usage;
  }
  const path = args[0] ?? "openagentfence.yml";
  const files = dependencies.files ?? nodeFileSystem;
  try {
    const metadata = await files.stat(path);
    if (!isBoundedFileSize(metadata.size))
      throw new PolicyDocumentError("POLICY_DOCUMENT_TOO_LARGE", ["policy: exceeds 1048576 bytes"]);
    const source = await files.readFile(path);
    if (Buffer.byteLength(source, "utf8") > MAX_CLI_INPUT_BYTES)
      throw new PolicyDocumentError("POLICY_DOCUMENT_TOO_LARGE", ["policy: exceeds 1048576 bytes"]);
    const document = parsePolicyDocumentSource(source, "policy");
    const report = validatePolicy(document);
    if (report.errors.length > 0) {
      writeIssues(io, report.errors);
      return CLI_EXIT.failure;
    }
    for (const warning of report.warnings) io.stdout(`warning: ${warning}\n`);
    io.stdout("policy valid\n");
    return CLI_EXIT.success;
  } catch (error) {
    if (error instanceof PolicyDocumentError) {
      writeIssues(io, error.errors);
    } else {
      io.stderr("policy input is invalid or unavailable\n");
    }
    return CLI_EXIT.failure;
  }
}

function writeIssues(io: CliIo, errors: readonly string[]): void {
  for (const error of [...errors].sort()) io.stderr(`error: ${error}\n`);
}
