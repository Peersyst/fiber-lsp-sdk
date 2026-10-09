import type { ITimer } from "../../session";

type SetTimeoutLike = (callback: () => void, delayMs: number) => unknown;

type ClearTimeoutLike = (handle: unknown) => void;

/**
 * Builds a timer over the runtime's own `setTimeout` and `clearTimeout`, read once and called without a receiver.
 * @returns The timer.
 */
export function runtimeTimer(): ITimer {
    const runtime = globalThis as { setTimeout?: unknown; clearTimeout?: unknown };
    const { setTimeout, clearTimeout } = runtime;
    if (typeof setTimeout !== "function" || typeof clearTimeout !== "function") {
        throw new TypeError("this runtime has no timer: pass one in the options");
    }
    // Unbound: a browser's `setTimeout` throws on any receiver but its window.
    const schedule = setTimeout as SetTimeoutLike;
    const cancel = clearTimeout as ClearTimeoutLike;
    return {
        schedule: (callback, delayMs) => {
            const handle = schedule(callback, delayMs);
            return () => cancel(handle);
        },
    };
}
