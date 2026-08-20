import {
  GuardProviderRuntimeError,
  validateGuardClassification,
  type GuardModelProvider,
} from "@openagentfence/core";
import type { GuardProviderOptions } from "./config.js";
import { GuardProviderConstructionError, validateProviderOptions } from "./config.js";
import { fetchJsonBounded, withConfiguredDeadline, withFallback } from "./http.js";
import {
  GUARD_CLASSIFICATION_TRANSPORT_SCHEMA,
  GUARD_SYSTEM_PROMPT,
  guardUserMessage,
  parseClassificationContent,
} from "./wire.js";

const DEFAULT_BASE_URL = "https://api.anthropic.com/v1";

/** Direct HTTP adapter for Anthropic Messages API version 2023-06-01. */
export function anthropicGuardProvider(options: GuardProviderOptions): GuardModelProvider {
  const validated = validateProviderOptions(options);
  if (typeof options.apiKey !== "string" || options.apiKey.length === 0) {
    throw new GuardProviderConstructionError("invalid_options");
  }
  const apiKey = options.apiKey;
  const baseUrl = secureBaseUrl(validated.baseUrl ?? DEFAULT_BASE_URL);
  const provider: GuardModelProvider = {
    name: "anthropic",
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
                  url: `${baseUrl}/messages`,
                  headers: {
                    "x-api-key": apiKey,
                    "anthropic-version": "2023-06-01",
                  },
                  body: {
                    model: validated.model,
                    max_tokens: request.budget?.maxTokens ?? constraints.maxTokens,
                    system: GUARD_SYSTEM_PROMPT,
                    messages: [{ role: "user", content: guardUserMessage(request) }],
                    output_config: {
                      format: {
                        type: "json_schema",
                        schema: GUARD_CLASSIFICATION_TRANSPORT_SCHEMA,
                      },
                    },
                  },
                },
                boundedConstraints,
              );
              const parsed = parseClassificationContent(anthropicContent(response));
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

function anthropicContent(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (record["stop_reason"] !== "end_turn") return null;
  const content = record["content"];
  if (!Array.isArray(content) || content.length !== 1) return null;
  const block: unknown = (content as unknown[])[0];
  if (typeof block !== "object" || block === null || Array.isArray(block)) return null;
  const blockRecord = block as Record<string, unknown>;
  return blockRecord["type"] === "text" ? blockRecord["text"] : null;
}

function secureBaseUrl(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol === "http:" && !isLoopback(parsed.hostname)) {
    throw new GuardProviderConstructionError("invalid_options");
  }
  return value.replace(/\/$/u, "");
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}
