import { blake2b } from "@noble/hashes/blake2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

const CKB_HASH_PERSONALIZATION = utf8ToBytes("ckb-default-hash");

const CKB_HASH_LENGTH = 32;

/**
 * Hashes bytes as CKB does: blake2b, 32 bytes, personalised `ckb-default-hash`.
 * @param data The bytes.
 * @returns The 32-byte digest.
 */
export function ckbBlake2b(data: Uint8Array): Uint8Array {
    return blake2b(data, { dkLen: CKB_HASH_LENGTH, personalization: CKB_HASH_PERSONALIZATION });
}
