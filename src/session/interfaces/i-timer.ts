export interface ITimer {
    /**
     * Runs a callback once, after a delay.
     * @param callback What to run.
     * @param delayMs Delay in milliseconds.
     * @returns A function that cancels the callback if it has not run yet.
     */
    schedule(callback: () => void, delayMs: number): () => void;
}
