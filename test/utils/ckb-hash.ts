import { blake2b } from "@noble/hashes/blake2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

// CKB's blake2b, written apart from src/ so a spec checks the SDK's hashing against an independent reference.
export function ckbHash(bytes: Uint8Array): Uint8Array {
    return blake2b(bytes, { dkLen: 32, personalization: utf8ToBytes("ckb-default-hash") });
}
