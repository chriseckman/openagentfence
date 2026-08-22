import type { GuardModelProvider } from "@openagentfence/core";
import type {
  CustomGuardProviderOptions,
  GuardProviderName,
  GuardProviderOptions,
} from "./config.js";
import { customGuardProvider } from "./custom.js";
import { ollamaGuardProvider } from "./ollama.js";
import { openAICompatibleGuardProvider } from "./openai-compatible.js";
import { openCodeGuardProvider } from "./opencode.js";
import { anthropicGuardProvider } from "./anthropic.js";
import { googleGuardProvider } from "./google.js";
import { xAIGuardProvider } from "./xai.js";

export function guardProvider(
  name: "custom",
  options: CustomGuardProviderOptions,
): GuardModelProvider;
export function guardProvider(
  name: Exclude<GuardProviderName, "custom">,
  options: GuardProviderOptions,
): GuardModelProvider;
export function guardProvider(
  name: GuardProviderName,
  options: GuardProviderOptions | CustomGuardProviderOptions,
): GuardModelProvider {
  if (name === "custom") {
    return customGuardProvider(options as CustomGuardProviderOptions);
  }
  if (name === "openai-compatible") return openAICompatibleGuardProvider(options);
  if (name === "ollama") return ollamaGuardProvider(options);
  if (name === "opencode") return openCodeGuardProvider(options);
  if (name === "anthropic") return anthropicGuardProvider(options);
  if (name === "google") return googleGuardProvider(options);
  return xAIGuardProvider(options);
}
