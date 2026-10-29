import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import type { ISignerStorage } from "@peersyst/fiber-lsp-sdk";

/**
 * Replaces a file in one step, readable by its owner only.
 * @param path The file to replace.
 * @param data What it holds afterwards.
 */
export function writeFileAtomically(path: string, data: string | Uint8Array): void {
    const tmp = `${path}.tmp`;
    // A leftover from a crash keeps its mode through a rewrite: removed so the new one is created 0600.
    rmSync(tmp, { force: true });
    writeFileSync(tmp, data, { mode: 0o600 });
    renameSync(tmp, path);
}

/**
 * Reads a storage file into its entries, refusing anything but a JSON object of strings.
 * @param path The file, which must exist.
 * @returns The entries.
 */
function readEntries(path: string): Map<string, string> {
    const text = readFileSync(path, "utf8");
    let parsed: unknown;
    try {
        parsed = JSON.parse(text);
    } catch {
        throw new Error(`${path} is not JSON`);
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error(`${path} must hold a JSON object`);
    }
    const entries = new Map<string, string>();
    for (const [key, value] of Object.entries(parsed)) {
        if (typeof value !== "string") throw new Error(`${path}: the value of ${JSON.stringify(key)} must be a string`);
        entries.set(key, value);
    }
    return entries;
}

export class FileSignerStorage implements ISignerStorage {
    private readonly entries: Map<string, string>;

    /**
     * Opens the store, loading the file when it exists and starting empty when it does not.
     * @param path The JSON file the store lives in.
     */
    constructor(private readonly path: string) {
        this.entries = existsSync(path) ? readEntries(path) : new Map();
    }

    /**
     * Reads a stored value.
     * @param key Key to read.
     * @returns The stored value, or `null` if the key was never written.
     */
    get(key: string): string | null {
        return this.entries.get(key) ?? null;
    }

    /**
     * Writes a value through to the file before it is visible to a later `get`.
     * @param key Key to write.
     * @param value Value to store.
     */
    set(key: string, value: string): void {
        const next = new Map(this.entries).set(key, value);
        writeFileAtomically(this.path, JSON.stringify(Object.fromEntries(next)));
        this.entries.set(key, value);
    }
}
