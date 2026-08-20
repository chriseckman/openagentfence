import {
  GuardProviderRuntimeError,
  guardTokenReservation,
  runWithDeadline,
  type GuardClassificationRequest,
  type GuardExecutionConstraints,
  type GuardModelProvider,
} from "@openagentfence/core";

export interface HttpJsonRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: unknown;
}

export async function fetchJsonBounded(
  request: HttpJsonRequest,
  constraints: GuardExecutionConstraints,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(request.url, {
      method: "POST",
      headers: { "content-type": "application/json", ...request.headers },
      body: JSON.stringify(request.body),
      signal: constraints.signal,
    });
  } catch {
    throw new GuardProviderRuntimeError(constraints.signal.aborted ? "cancelled" : "exception");
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new GuardProviderRuntimeError("unavailable");
  }
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > constraints.maxOutputBytes) {
    await response.body?.cancel().catch(() => undefined);
    throw new GuardProviderRuntimeError("oversized");
  }
  const bytes = await readBounded(response, constraints.maxOutputBytes);
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch {
    throw new GuardProviderRuntimeError("malformed");
  }
}

export async function withFallback(
  operation: () => Promise<unknown>,
  fallback: GuardModelProvider | undefined,
  request: GuardClassificationRequest,
  constraints: GuardExecutionConstraints,
): Promise<unknown> {
  try {
    return await operation();
  } catch (error) {
    const kind = error instanceof GuardProviderRuntimeError ? error.kind : "exception";
    if (kind === "cancelled" || kind === "timeout" || fallback === undefined) {
      throw error instanceof GuardProviderRuntimeError
        ? error
        : new GuardProviderRuntimeError("exception");
    }
    const tokens = guardTokenReservation(request, constraints);
    if (
      (constraints.remainingCalls !== undefined && constraints.remainingCalls < 2) ||
      (constraints.remainingTokens !== undefined && constraints.remainingTokens < tokens * 2) ||
      constraints.reserveDispatch?.({ calls: 1, tokens }) === false
    ) {
      throw new GuardProviderRuntimeError("budget_exhausted");
    }
    return fallback.classify(request, constraints);
  }
}

export async function withConfiguredDeadline(
  operation: (constraints: GuardExecutionConstraints) => Promise<unknown>,
  constraints: GuardExecutionConstraints,
  timeoutMs: number,
): Promise<unknown> {
  const deadline = Math.min(constraints.deadline, Date.now() + timeoutMs);
  const result = await runWithDeadline(
    (signal) => operation({ ...constraints, signal, deadline }),
    Math.max(0, deadline - Date.now()),
    constraints.signal,
  );
  if (!result.ok) {
    if (result.error instanceof GuardProviderRuntimeError) throw result.error;
    throw new GuardProviderRuntimeError(result.kind);
  }
  return result.value;
}

async function readBounded(response: Response, limit: number): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array();
  const reader: ReadableStreamDefaultReader<Uint8Array> = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) break;
      const chunk: Uint8Array = result.value;
      size += chunk.byteLength;
      if (size > limit) {
        await reader.cancel().catch(() => undefined);
        throw new GuardProviderRuntimeError("oversized");
      }
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof GuardProviderRuntimeError) throw error;
    throw new GuardProviderRuntimeError("exception");
  }
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}
