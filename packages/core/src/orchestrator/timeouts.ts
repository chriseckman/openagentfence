/**
 * Run an async operation with a deadline and an abort signal, distinguishing
 * timeout from parent cancellation from an ordinary exception. The deadline is
 * enforced by racing the operation against a timeout; parent cancellation
 * settles the race promptly even if the operation ignores its signal.
 */
export type DeadlineFailureKind = "timeout" | "cancelled" | "exception";

export type DeadlineResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly kind: DeadlineFailureKind; readonly error: unknown };

export async function runWithDeadline<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  parentSignal?: AbortSignal,
): Promise<DeadlineResult<T>> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let kind: DeadlineFailureKind = "exception";
  let failureError: unknown;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      kind = "timeout";
      controller.abort();
      reject(new Error("deadline exceeded"));
    }, timeoutMs);
  });

  const cancelledPromise = new Promise<never>((_, reject) => {
    const onAbort = (): void => {
      kind = "cancelled";
      controller.abort();
      reject(new Error("cancelled"));
    };
    if (parentSignal === undefined) {
      return;
    }
    if (parentSignal.aborted) {
      onAbort();
    } else {
      parentSignal.addEventListener("abort", onAbort, { once: true });
    }
  });

  try {
    const value = await Promise.race([
      fn(controller.signal).catch((error: unknown) => {
        if (kind === "exception") {
          failureError = error;
        }
        throw error;
      }),
      timeoutPromise,
      cancelledPromise,
    ]);
    return { ok: true, value };
  } catch (error) {
    return { ok: false, kind, error: failureError ?? error };
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}
