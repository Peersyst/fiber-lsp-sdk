export function asRecord(value: unknown, path: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${path} must be an object`);
    return value as Record<string, unknown>;
}

export function asString(value: unknown, path: string): string {
    if (typeof value !== "string") throw new Error(`${path} must be a string`);
    return value;
}

export function asNumber(value: unknown, path: string): number {
    if (typeof value !== "number") throw new Error(`${path} must be a number`);
    return value;
}

export function asBoolean(value: unknown, path: string): boolean {
    if (typeof value !== "boolean") throw new Error(`${path} must be a boolean`);
    return value;
}

export function asArray(value: unknown, path: string): unknown[] {
    if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
    return value;
}

export function asList<Item>(value: unknown, path: string, parse: (item: unknown, path: string) => Item): Item[] {
    return asArray(value, path).map((item, index) => parse(item, `${path}[${index}]`));
}

export function asPresent(value: unknown, path: string): unknown {
    if (value === undefined) throw new Error(`${path} is missing`);
    return value;
}

export function asNullable<Value>(value: unknown, path: string, parse: (value: unknown, path: string) => Value): Value | null {
    return asPresent(value, path) === null ? null : parse(value, path);
}

export function asStringFields<Field extends string>(value: unknown, path: string, fields: readonly Field[]): Record<Field, string> {
    const record = asRecord(value, path);
    const parsed = {} as Record<Field, string>;
    for (const field of fields) parsed[field] = asString(record[field], `${path}.${field}`);
    return parsed;
}
