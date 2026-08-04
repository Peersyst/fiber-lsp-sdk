import type { IAsyncSignerStorage, ISignerStorage } from "../../src/policy/index.js";

export class MemorySignerStorage implements ISignerStorage {
    readonly map = new Map<string, string>();
    readonly ops: string[] = [];

    get(key: string): string | null {
        this.ops.push(`get ${key}`);
        return this.map.get(key) ?? null;
    }

    set(key: string, value: string): void {
        this.ops.push(`set ${key}`);
        this.map.set(key, value);
    }
}

export class AsyncMemorySignerStorage implements IAsyncSignerStorage {
    readonly map = new Map<string, string>();
    readonly ops: string[] = [];

    // On by default: without latency an unserialized read-modify-write may not interleave.
    private readonly latencyTicks: number;

    constructor(latencyTicks = 2) {
        this.latencyTicks = latencyTicks;
    }

    async get(key: string): Promise<string | null> {
        this.ops.push(`get ${key}`);
        await this.wait();
        return this.map.get(key) ?? null;
    }

    async set(key: string, value: string): Promise<void> {
        this.ops.push(`set ${key}`);
        await this.wait();
        this.map.set(key, value);
    }

    private async wait(): Promise<void> {
        for (let tick = 0; tick < this.latencyTicks; tick++) await Promise.resolve();
    }
}
