/**
 * Host-injected persistence. Must survive restarts: a lost sign-once record turns a refusal into a double signature.
 */
export interface ISignerStorage {
    /**
     * Reads a stored value.
     * @param key Key to read.
     * @returns The stored value, or `null` if the key was never written.
     */
    get(key: string): string | null;
    /**
     * Writes a value, overwriting any previous one.
     * @param key Key to write.
     * @param value Value to store.
     */
    set(key: string, value: string): void;
}

/**
 * {@link ISignerStorage} for hosts whose persistence is asynchronous.
 */
export interface IAsyncSignerStorage {
    /**
     * Reads a stored value.
     * @param key Key to read.
     * @returns The stored value, or `null` if the key was never written.
     */
    get(key: string): Promise<string | null>;
    /**
     * Writes a value, overwriting any previous one.
     * @param key Key to write.
     * @param value Value to store.
     */
    set(key: string, value: string): Promise<void>;
}
