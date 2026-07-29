export interface SignerStorage {
    get(key: string): string | null;
    set(key: string, value: string): void;
}

export interface AsyncSignerStorage {
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
}
