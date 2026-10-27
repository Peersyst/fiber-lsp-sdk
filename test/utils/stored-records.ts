import type { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../mocks/policy";

type RecordingStorage = InMemorySignerStorage | AsyncInMemorySignerStorage;

export function storedAt(storage: RecordingStorage, key: string): unknown {
    const raw = storage.map.get(key);
    return raw === undefined ? undefined : JSON.parse(raw);
}

export function writes(storage: RecordingStorage): string[] {
    return storage.ops.filter((op) => op.startsWith("set ")).map((op) => op.slice("set ".length));
}
