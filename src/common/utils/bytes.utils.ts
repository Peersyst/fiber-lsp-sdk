/**
 * Compares two byte arrays lexicographically, a strict prefix sorting first.
 * @param a First array.
 * @param b Second array.
 * @returns Negative when `a` sorts first, positive when `b` does, zero on equality.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const length = Math.min(a.length, b.length);
    for (let i = 0; i < length; i++) {
        if (a[i] !== b[i]) return (a[i] ?? 0) - (b[i] ?? 0);
    }
    return a.length - b.length;
}
