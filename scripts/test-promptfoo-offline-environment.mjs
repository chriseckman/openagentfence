import { strict as assert } from "node:assert";
import { promptfooOfflineEnvironment } from "./promptfoo-offline-environment.mjs";

const environment = promptfooOfflineEnvironment(
  {
    PATH: "synthetic-path",
    TEMP: "synthetic-temp",
    AWS_SECRET_ACCESS_KEY: "OAF_TEST_SYNTHETIC_CREDENTIAL",
    OPENAI_API_KEY: "OAF_TEST_SYNTHETIC_CREDENTIAL",
    OPENAGENTFENCE_PROVIDER_KEY: "OAF_TEST_SYNTHETIC_CREDENTIAL",
    NPM_TOKEN: "OAF_TEST_SYNTHETIC_CREDENTIAL",
    GH_TOKEN: "OAF_TEST_SYNTHETIC_CREDENTIAL",
  },
  { configDirectory: "synthetic-config", logDirectory: "synthetic-logs" },
);

assert.equal(environment.PATH, "synthetic-path");
assert.equal(environment.PROMPTFOO_DISABLE_REMOTE_GENERATION, "true");
assert.equal(environment.PROMPTFOO_CONFIG_DIR, "synthetic-config");
for (const key of [
  "AWS_SECRET_ACCESS_KEY",
  "OPENAI_API_KEY",
  "OPENAGENTFENCE_PROVIDER_KEY",
  "NPM_TOKEN",
  "GH_TOKEN",
]) {
  assert.equal(key in environment, false);
}
process.stdout.write("Promptfoo offline environment regression passed\n");
