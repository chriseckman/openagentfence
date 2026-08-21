const inheritedRuntimeKeys = [
  "PATH",
  "Path",
  "SystemRoot",
  "WINDIR",
  "ComSpec",
  "PATHEXT",
  "TEMP",
  "TMP",
  "HOME",
  "USERPROFILE",
  "LOCALAPPDATA",
  "APPDATA",
  "ProgramData",
];

const forbiddenKey =
  /^(?:OPENAGENTFENCE_|AWS_|AZURE_|GCP_|GOOGLE_|NPM_|NODE_AUTH_TOKEN$|GH_TOKEN$|GITHUB_TOKEN$|OPENAI_|ANTHROPIC_|XAI_|GEMINI_|OLLAMA_|PROMPTFOO_API|CI_JOB_JWT)/iu;

/**
 * Creates the minimal child environment for the checked-in offline Promptfoo
 * example. Deliberately do not inherit arbitrary host state: promptfoo and its
 * transitive dependencies must not receive provider, cloud, package, GitHub,
 * or OpenAgentFence credentials during the local example gate.
 *
 * @param {NodeJS.ProcessEnv} source
 * @param {{ configDirectory: string, logDirectory: string }} paths
 */
export function promptfooOfflineEnvironment(source, paths) {
  if (!paths.configDirectory || !paths.logDirectory) {
    throw new Error("Promptfoo offline environment requires bounded temporary paths");
  }
  const environment = {};
  for (const key of inheritedRuntimeKeys) {
    const value = source[key];
    if (typeof value === "string" && value !== "") environment[key] = value;
  }
  Object.assign(environment, {
    CI: "true",
    FORCE_COLOR: "0",
    PROMPTFOO_DISABLE_TELEMETRY: "1",
    PROMPTFOO_DISABLE_UPDATE: "1",
    PROMPTFOO_DISABLE_REMOTE_GENERATION: "true",
    PROMPTFOO_DISABLE_SHARING: "1",
    PROMPTFOO_SELF_HOSTED: "1",
    PROMPTFOO_CACHE_ENABLED: "false",
    PROMPTFOO_CONFIG_DIR: paths.configDirectory,
    PROMPTFOO_LOG_DIR: paths.logDirectory,
  });
  for (const key of Object.keys(environment)) {
    if (forbiddenKey.test(key)) {
      throw new Error("Promptfoo offline environment must not inherit a credential namespace");
    }
  }
  return Object.freeze(environment);
}

export function promptfooOfflineEnvironmentKeys() {
  return [...inheritedRuntimeKeys];
}
