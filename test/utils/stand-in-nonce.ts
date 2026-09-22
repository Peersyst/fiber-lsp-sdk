import { hexToBytes } from "@noble/hashes/utils.js";
import { nonceGen } from "@scure/btc-signer/musig2.js";
import { deriveChannelKeys, pubkeyOf } from "../../src/derivation";
import { loadInteropVectors } from "./interop-vectors";

const PEER_KEYS = deriveChannelKeys(hexToBytes(loadInteropVectors().digest.remote.seed));

/**
 * Builds valid points no device published: enough for every path that answers before the node would verify.
 * @param randByte Fills the nonce randomness.
 * @returns The 66-byte aggregated nonce.
 */
export function standInAggregatedNonce(randByte: number): Uint8Array {
    const rand = new Uint8Array(32).fill(randByte);
    return nonceGen(pubkeyOf(PEER_KEYS.fundingKey), PEER_KEYS.fundingKey, undefined, undefined, undefined, rand).public;
}
