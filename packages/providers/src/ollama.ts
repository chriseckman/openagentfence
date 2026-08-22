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

const DEFAULT_BASE_URL = "http://127.0.0.1:11434/api";

/** Direct HTTP adapter for Ollama's documented non-streaming chat API. */
export function ollamaGuardProvider(options: GuardProviderOptions): GuardModelProvider {
  const validated = validateProviderOptions(options);
  const baseUrl = (validated.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/u, "");
  const parsedBase = new URL(baseUrl);
  if (!isLoopback(parsedBase.hostname) || options.apiKey !== undefined) {
    throw new GuardProviderConstructionError("invalid_options");
  }
  const provider: GuardModelProvider = {
    name: "ollama",
    model: validated.model,
    makesExternalCalls: false,
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
                  url: `${baseUrl}/chat`,
                  headers: {},
                  body: {
                    model: validated.model,
                    messages: [
                      { role: "system", content: GUARD_SYSTEM_PROMPT },
                      { role: "user", content: guardUserMessage(request) },
                    ],
                    format: GUARD_CLASSIFICATION_SCHEMA,
                    options: {
                      temperature: 0,
                      num_predict: request.budget?.maxTokens ?? constraints.maxTokens,
                    },
                    stream: false,
                  },
                },
                boundedConstraints,
              );
              const content = ollamaContent(response);
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

function ollamaContent(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  if ((value as Record<string, unknown>)["done"] !== true) return null;
  const message = (value as Record<string, unknown>)["message"];
  if (typeof message !== "object" || message === null || Array.isArray(message)) return null;
  return (message as Record<string, unknown>)["content"];
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}
