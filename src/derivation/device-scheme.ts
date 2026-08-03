/**
 * Derivations the SDK owns. The domain separators are inside the hash: changing one strands every channel opened under it.
 */
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { MASTER_SEED_LENGTH, MAX_CHANNEL_INDEX, MAX_COMMITMENT_NUMBER, NONCE_CONTEXTS } from "./derivation.constants.js";
import type { FiberChannelKeys, NonceContext } from "./derivation.types.js";
import { derivePrivateKey, getCommitmentPoint } from "./fiber-scheme.js";
import { assertBytes, assertUnsignedInteger, ckbBlake2b } from "./utils/index.js";

/**
 * Derives the wallet identity key, which answers the signer-session challenge.
 * @param masterSeed The 32-byte master seed.
 * @returns The 32-byte wallet identity key.
 */
export function deriveWalletIdentityKey(masterSeed: Uint8Array): Uint8Array {
    assertBytes("masterSeed", masterSeed, MASTER_SEED_LENGTH);
    return ckbBlake2b(masterSeed, utf8ToBytes("wallet identity"));
}

/**
 * Derives the seed fiber's `InMemorySigner` expands into one channel's secrets.
 * @param masterSeed The 32-byte master seed.
 * @param channelIndex Index of the channel, up to `MAX_CHANNEL_INDEX`.
 * @returns The 32-byte channel seed.
 */
export function deriveChannelSeed(masterSeed: Uint8Array, channelIndex: number): Uint8Array {
    assertBytes("masterSeed", masterSeed, MASTER_SEED_LENGTH);
    assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
    return ckbBlake2b(masterSeed, utf8ToBytes(`fiber channel ${channelIndex}`));
}

/**
 * Derives the musig2 secret nonce seed for one (commitment number, context) slot.
 * @param keys The channel's four secrets.
 * @param commitmentNumber The commitment number, up to `MAX_COMMITMENT_NUMBER`.
 * @param context The signature the nonce is for.
 * @returns The 32-byte nonce seed.
 */
export function deriveNonceSeed(keys: FiberChannelKeys, commitmentNumber: number, context: NonceContext): Uint8Array {
    assertUnsignedInteger("commitmentNumber", commitmentNumber, MAX_COMMITMENT_NUMBER);
    if (!NONCE_CONTEXTS.includes(context)) {
        throw new TypeError(`context must be one of ${NONCE_CONTEXTS.join(", ")}, got ${String(context)}`);
    }
    const commitmentPoint = getCommitmentPoint(keys.commitmentSeed, commitmentNumber);
    return ckbBlake2b(derivePrivateKey(keys.musig2BaseNonce, commitmentPoint), utf8ToBytes(context));
}
