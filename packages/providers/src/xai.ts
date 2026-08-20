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

const DEFAULT_BASE_URL = "https://api.x.ai/v1";

/** Direct HTTP adapter for xAI's recommended v1 Responses protocol. */
export function xAIGuardProvider(options: GuardProviderOptions): GuardModelProvider {
  const validated = validateProviderOptions(options);
  if (typeof options.apiKey !== "string" || options.apiKey.length === 0) {
    throw new GuardProviderConstructionError("invalid_options");
  }
  const apiKey = options.apiKey;
  const baseUrl = secureBaseUrl(validated.baseUrl ?? DEFAULT_BASE_URL);
  const provider: GuardModelProvider = {
    name: "xai",
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
                  url: `${baseUrl}/responses`,
                  headers: { authorization: `Bearer ${apiKey}` },
                  body: {
                    model: validated.model,
                    input: [
                      { role: "system", content: GUARD_SYSTEM_PROMPT },
                      { role: "user", content: guardUserMessage(request) },
                    ],
                    store: false,
                    text: {
                      format: {
                        type: "json_schema",
                        name: "openagentfence_guard_classification",
                        schema: GUARD_CLASSIFICATION_SCHEMA,
                        strict: true,
                      },
                    },
                    max_output_tokens: request.budget?.maxTokens ?? constraints.maxTokens,
                  },
                },
                boundedConstraints,
              );
              const parsed = parseClassificationContent(xAIContent(response));
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

function xAIContent(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (record["object"] !== "response" || record["status"] !== "completed") return null;
  if (record["error"] !== undefined && record["error"] !== null) return null;
  const output = record["output"];
  if (!Array.isArray(output) || output.length !== 1) return null;
  const message: unknown = (output as unknown[])[0];
  if (typeof message !== "object" || message === null || Array.isArray(message)) return null;
  const messageRecord = message as Record<string, unknown>;
  if (messageRecord["type"] !== "message") return null;
  const content = messageRecord["content"];
  if (!Array.isArray(content) || content.length !== 1) return null;
  const part: unknown = (content as unknown[])[0];
  if (typeof part !== "object" || part === null || Array.isArray(part)) return null;
  const partRecord = part as Record<string, unknown>;
  return partRecord["type"] === "output_text" ? partRecord["text"] : null;
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
