import { ckbBlake2b } from "../../common";

/**
 * Port of fiber's `blake2b_hash_with_salt`.
 * @param data Data to hash.
 * @param salt Domain separator, hashed before the data, opposite to the argument order.
 * @returns The 32-byte digest.
 */
export function blake2bHashWithSalt(data: Uint8Array, salt: Uint8Array): Uint8Array {
    return ckbBlake2b(salt, data);
}
