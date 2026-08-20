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

const DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta";

/** Direct HTTP adapter for the Gemini v1beta generateContent protocol. */
export function googleGuardProvider(options: GuardProviderOptions): GuardModelProvider {
  const validated = validateProviderOptions(options);
  if (typeof options.apiKey !== "string" || options.apiKey.length === 0) {
    throw new GuardProviderConstructionError("invalid_options");
  }
  const apiKey = options.apiKey;
  const baseUrl = secureBaseUrl(validated.baseUrl ?? DEFAULT_BASE_URL);
  const provider: GuardModelProvider = {
    name: "google",
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
                  url: `${baseUrl}/models/${encodeURIComponent(validated.model)}:generateContent`,
                  headers: { "x-goog-api-key": apiKey },
                  body: {
                    systemInstruction: { parts: [{ text: GUARD_SYSTEM_PROMPT }] },
                    contents: [{ role: "user", parts: [{ text: guardUserMessage(request) }] }],
                    generationConfig: {
                      responseFormat: {
                        text: {
                          mimeType: "application/json",
                          schema: GUARD_CLASSIFICATION_TRANSPORT_SCHEMA,
                        },
                      },
                      candidateCount: 1,
                      maxOutputTokens: request.budget?.maxTokens ?? constraints.maxTokens,
                      temperature: 0,
                    },
                  },
                },
                boundedConstraints,
              );
              const parsed = parseClassificationContent(googleContent(response));
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

function googleContent(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const feedback = record["promptFeedback"];
  if (typeof feedback === "object" && feedback !== null && !Array.isArray(feedback)) {
    if ((feedback as Record<string, unknown>)["blockReason"] !== undefined) return null;
  }
  const candidates = record["candidates"];
  if (!Array.isArray(candidates) || candidates.length !== 1) return null;
  const candidate: unknown = (candidates as unknown[])[0];
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) return null;
  const candidateRecord = candidate as Record<string, unknown>;
  if (candidateRecord["finishReason"] !== "STOP") return null;
  const content = candidateRecord["content"];
  if (typeof content !== "object" || content === null || Array.isArray(content)) return null;
  const parts = (content as Record<string, unknown>)["parts"];
  if (!Array.isArray(parts) || parts.length !== 1) return null;
  const part: unknown = (parts as unknown[])[0];
  if (typeof part !== "object" || part === null || Array.isArray(part)) return null;
  return (part as Record<string, unknown>)["text"];
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
