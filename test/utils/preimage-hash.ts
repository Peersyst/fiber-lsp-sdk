import { sha256 } from "@noble/hashes/sha2.js";
import type { TlcHashAlgorithm } from "../../src/common";
import { PREIMAGE_LENGTH, ckbBlake2b } from "../../src/common";

// Fiber's `HashAlgorithm::hash`, which the node checks a fulfil's preimage with and `verified_watch_preimage` a held one
// (`watchtower/actor.rs:1212-1231`).
export function hashPreimage(algorithm: TlcHashAlgorithm, preimage: Uint8Array): Uint8Array {
    if (preimage.length !== PREIMAGE_LENGTH) throw new Error(`a preimage is ${PREIMAGE_LENGTH} bytes`);
    return algorithm === "sha256" ? sha256(preimage) : ckbBlake2b(preimage);
}
