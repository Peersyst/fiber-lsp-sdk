/**
 * Deep-copies a JSON value with one field replaced, the field named by a path like `tlcs[0].amount`; `undefined` removes it.
 * @param value Value to copy.
 * @param path Path of the field to replace.
 * @param replacement New value, or `undefined` to delete the field.
 * @returns The copy.
 */
export function withField<T>(value: T, path: string, replacement: unknown): T {
    const copy: T = structuredClone(value);
    const tokens = path.match(/[^.[\]]+/g) ?? [];
    const last = tokens[tokens.length - 1];
    if (last === undefined) throw new Error(`empty field path: ${path}`);
    let target: unknown = copy;
    for (const token of tokens.slice(0, -1)) target = (target as Record<string, unknown>)[token];
    const container = target as Record<string, unknown>;
    if (replacement === undefined) delete container[last];
    else container[last] = replacement;
    return copy;
}
