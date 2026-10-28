import { utf8ToBytes } from "@noble/hashes/utils.js";
import { assertBytes, assertOneOf, assertUnsignedInteger, ckbBlake2b } from "../common";
import { MASTER_SEED_LENGTH, MAX_CHANNEL_INDEX, MAX_COMMITMENT_NUMBER, MAX_INVOICE_INDEX, NONCE_CONTEXTS } from "./derivation.constants";
import type { FiberChannelKeys, NonceContext } from "./derivation.types";
import { derivePrivateKey, getCommitmentPoint } from "./fiber-scheme";

/**
 * Derives the wallet identity key, the same on every device restored from one seed.
 * @param masterSeed The master seed.
 * @returns The 32-byte key.
 */
export function deriveWalletIdentityKey(masterSeed: Uint8Array): Uint8Array {
    assertBytes("masterSeed", masterSeed, MASTER_SEED_LENGTH);
    return ckbBlake2b(masterSeed, utf8ToBytes("wallet identity"));
}

/**
 * Derives the seed fiber's `InMemorySigner` expands into one channel's secrets.
 * @param masterSeed The master seed.
 * @param channelIndex The channel index.
 * @returns The 32-byte channel seed.
 */
export function deriveChannelSeed(masterSeed: Uint8Array, channelIndex: number): Uint8Array {
    assertBytes("masterSeed", masterSeed, MASTER_SEED_LENGTH);
    assertUnsignedInteger("channelIndex", channelIndex, MAX_CHANNEL_INDEX);
    return ckbBlake2b(masterSeed, utf8ToBytes(`fiber channel ${channelIndex}`));
}

/**
 * Derives the preimage of the device's hold invoice of one index.
 * @param masterSeed The master seed.
 * @param invoiceIndex The invoice index.
 * @returns The 32-byte preimage.
 */
export function deriveHoldInvoicePreimage(masterSeed: Uint8Array, invoiceIndex: number): Uint8Array {
    assertBytes("masterSeed", masterSeed, MASTER_SEED_LENGTH);
    assertUnsignedInteger("invoiceIndex", invoiceIndex, MAX_INVOICE_INDEX);
    return ckbBlake2b(masterSeed, utf8ToBytes(`hold invoice ${invoiceIndex}`));
}

/**
 * Derives the musig2 secret nonce seed for one (commitment number, context) slot.
 * @param keys The channel's secrets.
 * @param commitmentNumber The commitment number.
 * @param context The signature the nonce is for.
 * @returns The 32-byte nonce seed.
 */
export function deriveNonceSeed(keys: FiberChannelKeys, commitmentNumber: number, context: NonceContext): Uint8Array {
    assertUnsignedInteger("commitmentNumber", commitmentNumber, MAX_COMMITMENT_NUMBER);
    assertOneOf("context", context, NONCE_CONTEXTS);
    const commitmentPoint = getCommitmentPoint(keys.commitmentSeed, commitmentNumber);
    return ckbBlake2b(derivePrivateKey(keys.musig2BaseNonce, commitmentPoint), utf8ToBytes(context));
}
