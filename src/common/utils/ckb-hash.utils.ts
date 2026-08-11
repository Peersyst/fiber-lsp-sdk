import { blake2b } from "@noble/hashes/blake2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

const CKB_PERSONALIZATION = utf8ToBytes("ckb-default-hash");

const DIGEST_LENGTH = 32;

const BLAKE160_LENGTH = 20;

/**
 * CKB-style blake2b-256: the personalization is what makes digests match CKB and fiber.
 * @param chunks Byte chunks, hashed as one concatenated input.
 * @returns The 32-byte digest.
 */
export function ckbBlake2b(...chunks: Uint8Array[]): Uint8Array {
    return blake2b(concatBytes(...chunks), { dkLen: DIGEST_LENGTH, personalization: CKB_PERSONALIZATION });
}

/**
 * Port of CKB's `blake160`: the first 20 bytes of the CKB blake2b-256 digest.
 * @param chunks Byte chunks, hashed as one concatenated input.
 * @returns The 20-byte truncation.
 */
export function blake160(...chunks: Uint8Array[]): Uint8Array {
    return ckbBlake2b(...chunks).slice(0, BLAKE160_LENGTH);
}
