import { equalBytes } from "@noble/curves/utils.js";
import { Session, nonceGen } from "@scure/btc-signer/musig2.js";
import { COMPRESSED_POINT_LENGTH, MESSAGE_DIGEST_LENGTH, MUSIG_PARTICIPANTS, PUBLIC_NONCE_LENGTH, assertBytes } from "../common";
import type { FiberChannelKeys, NonceContext } from "../derivation";
import { deriveNonceSeed, getCommitmentPoint, pubkeyOf } from "../derivation";
import { PARTIAL_SIGNATURE_LENGTH } from "./signer.constants";
import type { BasePublicKeys, PartialSignRequest } from "./signer.types";

/**
 * Derives the public halves of the channel's base keys the device shares with the node.
 * @param keys The channel's four secrets.
 * @returns The 33-byte compressed funding and TLC base public keys.
 */
export function getBasePublicKeys(keys: FiberChannelKeys): BasePublicKeys {
    return { fundingPubkey: pubkeyOf(keys.fundingKey), tlcBasePubkey: pubkeyOf(keys.tlcBaseKey) };
}

/**
 * Derives the public commitment point of a commitment number.
 * @param keys The channel's four secrets.
 * @param commitmentNumber The commitment number, up to `MAX_COMMITMENT_NUMBER`.
 * @returns The 33-byte compressed commitment point.
 */
export function getChannelCommitmentPoint(keys: FiberChannelKeys, commitmentNumber: number): Uint8Array {
    return getCommitmentPoint(keys.commitmentSeed, commitmentNumber);
}

/**
 * Derives the deterministic musig2 public nonce of one signing slot, publishable before the message exists.
 * @param keys The channel's four secrets.
 * @param commitmentNumber The commitment number, up to `MAX_COMMITMENT_NUMBER`.
 * @param context The signature the nonce is for.
 * @returns The 66-byte public nonce.
 */
export function getPublicNonce(keys: FiberChannelKeys, commitmentNumber: number, context: NonceContext): Uint8Array {
    return generateNonces(keys, commitmentNumber, context).public;
}

/**
 * Produces the device's musig2 partial signature over a 32-byte digest, regenerating the slot's deterministic nonce.
 * @param keys The channel's four secrets.
 * @param request The signing request as the node sent it.
 * @returns The 32-byte partial signature.
 */
export function partialSign(keys: FiberChannelKeys, request: PartialSignRequest): Uint8Array {
    const { orderedPublicKeys, aggregatedNonce, message, commitmentNumber, context } = request;
    if (!Array.isArray(orderedPublicKeys) || orderedPublicKeys.length !== MUSIG_PARTICIPANTS) {
        throw new TypeError(`orderedPublicKeys must be exactly ${MUSIG_PARTICIPANTS} public keys`);
    }
    const [firstKey, secondKey] = orderedPublicKeys;
    assertBytes("orderedPublicKeys[0]", firstKey, COMPRESSED_POINT_LENGTH);
    assertBytes("orderedPublicKeys[1]", secondKey, COMPRESSED_POINT_LENGTH);
    assertBytes("aggregatedNonce", aggregatedNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("message", message, MESSAGE_DIGEST_LENGTH);
    if (equalBytes(firstKey, secondKey)) {
        throw new TypeError("orderedPublicKeys must be two distinct public keys");
    }
    const fundingPubkey = pubkeyOf(keys.fundingKey);
    if (!equalBytes(firstKey, fundingPubkey) && !equalBytes(secondKey, fundingPubkey)) {
        throw new TypeError("orderedPublicKeys must include the channel funding public key");
    }

    // Deterministic nonces are safe only once the policy layer has claimed this slot for this exact session: one key list, one
    // aggregated nonce, one message. Three sessions over one slot recover the funding key, see docs/signing.md.
    const nonces = generateNonces(keys, commitmentNumber, context);
    const session = new Session(aggregatedNonce, orderedPublicKeys, message);
    const partialSignature = session.sign(nonces.secret, keys.fundingKey);
    // Checked on the way out: the dependency floats on a caret range, and the wire size is a protocol commitment.
    assertBytes("partialSignature", partialSignature, PARTIAL_SIGNATURE_LENGTH);
    return partialSignature;
}

/**
 * Regenerates the deterministic secret and public nonce of one signing slot.
 * @param keys The channel's four secrets.
 * @param commitmentNumber The commitment number the nonce belongs to.
 * @param context The signature the nonce is for.
 * @returns The BIP-327 nonce pair.
 */
function generateNonces(keys: FiberChannelKeys, commitmentNumber: number, context: NonceContext) {
    const nonceSeed = deriveNonceSeed(keys, commitmentNumber, context);
    return nonceGen(pubkeyOf(keys.fundingKey), keys.fundingKey, undefined, undefined, undefined, nonceSeed);
}
