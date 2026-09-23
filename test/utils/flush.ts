export function flush(): Promise<void> {
    return new Promise((resolve) => setImmediate(resolve));
}
