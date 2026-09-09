import type { IAsyncSignerStorage, ISignerStorage } from "../../../src/policy";

export class InMemorySignerStorage implements ISignerStorage {
    readonly map = new Map<string, string>();
    readonly ops: string[];

    // Shareable so a test over two storages sees the order the writes landed in.
    constructor(ops: string[] = []) {
        this.ops = ops;
    }

    get(key: string): string | null {
        this.ops.push(`get ${key}`);
        return this.map.get(key) ?? null;
    }

    set(key: string, value: string): void {
        this.ops.push(`set ${key}`);
        this.map.set(key, value);
    }
}

export class AsyncInMemorySignerStorage implements IAsyncSignerStorage {
    readonly map = new Map<string, string>();
    readonly ops: string[];

    // On by default: without latency an unserialized read-modify-write may not interleave.
    private readonly latencyTicks: number;

    constructor(latencyTicks = 2, ops: string[] = []) {
        this.latencyTicks = latencyTicks;
        this.ops = ops;
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
