import { blake2b } from "@noble/hashes/blake2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { DIGEST_LENGTH } from "../derivation.constants.js";

const CKB_PERSONALIZATION = utf8ToBytes("ckb-default-hash");

/**
 * CKB-style blake2b-256: the personalization is what makes digests match CKB and fiber.
 * @param chunks Byte chunks, hashed as one concatenated input.
 * @returns The 32-byte digest.
 */
export function ckbBlake2b(...chunks: Uint8Array[]): Uint8Array {
    return blake2b(concatBytes(...chunks), { dkLen: DIGEST_LENGTH, personalization: CKB_PERSONALIZATION });
}

/**
 * Port of fiber's `blake2b_hash_with_salt`.
 * @param data Data to hash.
 * @param salt Domain separator, hashed before the data, opposite to the argument order.
 * @returns The 32-byte digest.
 */
export function blake2bHashWithSalt(data: Uint8Array, salt: Uint8Array): Uint8Array {
    return ckbBlake2b(salt, data);
}
