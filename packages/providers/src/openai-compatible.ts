import {
  GuardProviderRuntimeError,
  validateGuardClassification,
  type GuardModelProvider,
} from "@openagentfence/core";
import type { GuardProviderOptions } from "./config.js";
import { GuardProviderConstructionError, validateProviderOptions } from "./config.js";
import { fetchJsonBounded, withConfiguredDeadline, withFallback } from "./http.js";
import {
  GUARD_CLASSIFICATION_SCHEMA,
  GUARD_SYSTEM_PROMPT,
  guardUserMessage,
  parseClassificationContent,
} from "./wire.js";

const DEFAULT_BASE_URL = "https://api.openai.com/v1";

/** Direct HTTP adapter for the documented OpenAI Chat Completions protocol. */
export function openAICompatibleGuardProvider(options: GuardProviderOptions): GuardModelProvider {
  return createOpenAIChatGuardProvider(
    "openai-compatible",
    options,
    DEFAULT_BASE_URL,
    "max_completion_tokens",
  );
}

export function createOpenAIChatGuardProvider(
  name: string,
  options: GuardProviderOptions,
  defaultBaseUrl: string,
  tokenField: "max_completion_tokens" | "max_tokens",
): GuardModelProvider {
  const validated = validateProviderOptions(options);
  if (typeof options.apiKey !== "string" || options.apiKey.length === 0) {
    throw new GuardProviderConstructionError("invalid_options");
  }
  const apiKey = options.apiKey;
  const baseUrl = normalizeBaseUrl(validated.baseUrl ?? defaultBaseUrl);
  const provider: GuardModelProvider = {
    name,
    model: validated.model,
    makesExternalCalls: true,
    async classify(request, constraints) {
      if (!validated.roles.has(request.role)) {
        throw new GuardProviderRuntimeError("unavailable");
      }
      return withFallback(
        () =>
          withConfiguredDeadline(
            async (boundedConstraints) => {
              const response = await fetchJsonBounded(
                {
                  url: `${baseUrl}/chat/completions`,
                  headers: { authorization: `Bearer ${apiKey}` },
                  body: {
                    model: validated.model,
                    messages: [
                      { role: "system", content: GUARD_SYSTEM_PROMPT },
                      { role: "user", content: guardUserMessage(request) },
                    ],
                    response_format: {
                      type: "json_schema",
                      json_schema: {
                        name: "openagentfence_guard_classification",
                        strict: true,
                        schema: GUARD_CLASSIFICATION_SCHEMA,
                      },
                    },
                    [tokenField]: request.budget?.maxTokens ?? constraints.maxTokens,
                    temperature: 0,
                    stream: false,
                  },
                },
                boundedConstraints,
              );
              const content = openAIContent(response);
              const parsed = parseClassificationContent(content);
              if (validateGuardClassification(parsed) === null) {
                throw new GuardProviderRuntimeError("malformed");
              }
              return parsed;
            },
            constraints,
            validated.timeoutMs,
          ),
        validated.fallback,
        request,
        constraints,
      );
    },
  };
  return Object.freeze(provider);
}

function openAIContent(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const choices = (value as Record<string, unknown>)["choices"];
  if (!Array.isArray(choices) || choices.length !== 1) return null;
  const first: unknown = (choices as unknown[])[0];
  if (typeof first !== "object" || first === null || Array.isArray(first)) return null;
  if ((first as Record<string, unknown>)["finish_reason"] !== "stop") return null;
  const message = (first as Record<string, unknown>)["message"];
  if (typeof message !== "object" || message === null || Array.isArray(message)) return null;
  if ((message as Record<string, unknown>)["refusal"] !== undefined) return null;
  return (message as Record<string, unknown>)["content"];
}

function normalizeBaseUrl(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol === "http:" && !isLoopback(parsed.hostname)) {
    throw new GuardProviderConstructionError("invalid_options");
  }
  return value.replace(/\/$/u, "");
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}
