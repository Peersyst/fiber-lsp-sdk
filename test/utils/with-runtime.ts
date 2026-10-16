export type RuntimeGlobals = { fetch?: unknown; setTimeout?: unknown; clearTimeout?: unknown };

/**
 * Runs with some of the runtime's globals replaced, putting back exactly those once the run returns or throws.
 * @param patch The globals to replace, `undefined` included to remove one.
 * @param run What to run meanwhile.
 * @returns What the run returned.
 */
export function withRuntime<Value>(patch: RuntimeGlobals, run: () => Value): Value {
    const runtime = globalThis as RuntimeGlobals;
    const original = (Object.keys(patch) as (keyof RuntimeGlobals)[]).map((key) => [key, runtime[key]] as const);
    Object.assign(runtime, patch);
    try {
        return run();
    } finally {
        for (const [key, value] of original) runtime[key] = value;
    }
}
