import { malformedWireField } from "./field";
import type { WireField } from "./wire.types";

const FLAG_SEPARATOR = "|";

/**
 * Reads a field as fiber's flag set: names joined by `|`, `""` for none.
 * @param field Field to read.
 * @param names The names the set may hold.
 * @returns The names, in the order the wire gives them.
 */
export function decodeFlags<Names extends readonly string[]>(field: WireField, names: Names): Names[number][] {
    if (typeof field.value !== "string") malformedWireField(field, "must be a string of flag names");
    if (field.value === "") return [];
    const accepted: readonly string[] = names;
    const flags = field.value.split(FLAG_SEPARATOR);
    // Fiber writes each name once, unpadded.
    if (flags.some((flag) => !accepted.includes(flag)) || new Set(flags).size !== flags.length) {
        malformedWireField(field, `must be distinct names among ${names.join(", ")}, joined by ${FLAG_SEPARATOR}`);
    }
    return flags as Names[number][];
}
