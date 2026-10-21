import { schnorr } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { Session, keyAggExport, keyAggregate, nonceAggregate, nonceGen } from "@scure/btc-signer/musig2.js";
import {
    MESSAGE_DIGEST_LENGTH,
    MUSIG_PARTICIPANTS,
    PARTIAL_SIGNATURE_LENGTH,
    PUBLIC_NONCE_LENGTH,
    SCHNORR_SIGNATURE_LENGTH,
    assertBytes,
    assertTwoDistinctKeys,
} from "../common";
import type { BasePublicKeys, FiberChannelKeys, NonceContext } from "../derivation";
import { deriveNonceSeed, getCommitmentPoint, pubkeyOf } from "../derivation";
import type { SignSession } from "../policy";
import type { CosignSession, PartialSignRequest } from "./signer.types";

/**
 * Derives the channel's funding and TLC base public keys.
 * @param keys The channel's secrets.
 * @returns The 33-byte compressed keys.
 */
export function getBasePublicKeys(keys: FiberChannelKeys): BasePublicKeys {
    return { fundingPubkey: pubkeyOf(keys.fundingKey), tlcBasePubkey: pubkeyOf(keys.tlcBaseKey) };
}

/**
 * Derives the commitment point of a commitment number.
 * @param keys The channel's secrets.
 * @param commitmentNumber The commitment number.
 * @returns The 33-byte compressed commitment point.
 */
export function getChannelCommitmentPoint(keys: FiberChannelKeys, commitmentNumber: number): Uint8Array {
    return getCommitmentPoint(keys.commitmentSeed, commitmentNumber);
}

/**
 * Derives the deterministic musig2 public nonce of one signing slot.
 * @param keys The channel's secrets.
 * @param commitmentNumber The commitment number.
 * @param context The signature the nonce is for.
 * @returns The 66-byte public nonce.
 */
export function getPublicNonce(keys: FiberChannelKeys, commitmentNumber: number, context: NonceContext): Uint8Array {
    return generateNonces(keys, commitmentNumber, context).public;
}

/**
 * Aggregates the device's public nonce with the peer's (BIP-327 `NonceAgg`).
 * @param devicePublicNonce The device's public nonce.
 * @param peerPublicNonce The peer's public nonce.
 * @returns The 66-byte aggregated nonce.
 */
export function aggregatePublicNonces(devicePublicNonce: Uint8Array, peerPublicNonce: Uint8Array): Uint8Array {
    assertBytes("devicePublicNonce", devicePublicNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("peerPublicNonce", peerPublicNonce, PUBLIC_NONCE_LENGTH);
    return nonceAggregate([devicePublicNonce, peerPublicNonce]);
}

/**
 * Produces the device's musig2 partial signature over a 32-byte digest.
 * @param keys The channel's secrets.
 * @param request The signing request.
 * @returns The 32-byte partial signature.
 */
export function partialSign(keys: FiberChannelKeys, request: PartialSignRequest): Uint8Array {
    const { orderedPublicKeys, aggregatedNonce, message, commitmentNumber, context } = request;
    assertCosignerKeys(keys, request);
    assertBytes("aggregatedNonce", aggregatedNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("message", message, MESSAGE_DIGEST_LENGTH);

    // Safe only once the policy has claimed the slot for this exact session: three over one slot recover the funding key.
    const nonces = generateNonces(keys, commitmentNumber, context);
    const session = new Session(aggregatedNonce, orderedPublicKeys, message);
    const partialSignature = session.sign(nonces.secret, keys.fundingKey);
    // The dependency floats on a caret range; the wire size is a protocol commitment.
    assertBytes("partialSignature", partialSignature, PARTIAL_SIGNATURE_LENGTH);
    return partialSignature;
}

/**
 * Verifies the peer's partial signature of a session.
 * @param keys The channel's secrets.
 * @param session The session, with each side's public nonce.
 * @param peerPartialSignature The peer's partial signature.
 * @returns Whether it verifies, taking the aggregated nonce as given.
 */
export function verifyPeerPartialSignature(keys: FiberChannelKeys, session: CosignSession, peerPartialSignature: Uint8Array): boolean {
    const deviceIndex = assertCosignerKeys(keys, session);
    assertBytes("aggregatedNonce", session.aggregatedNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("message", session.message, MESSAGE_DIGEST_LENGTH);
    assertBytes("devicePublicNonce", session.devicePublicNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("peerPublicNonce", session.peerPublicNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("peerPartialSignature", peerPartialSignature, PARTIAL_SIGNATURE_LENGTH);
    const publicNonces =
        deviceIndex === 0 ? [session.devicePublicNonce, session.peerPublicNonce] : [session.peerPublicNonce, session.devicePublicNonce];
    const musig = new Session(session.aggregatedNonce, session.orderedPublicKeys, session.message);
    return musig.partialSigVerify(peerPartialSignature, publicNonces, 1 - deviceIndex);
}

/**
 * Aggregates a session's partial signatures into a BIP-340 signature the aggregated key accepts.
 * @param session The session.
 * @param partialSignatures One partial signature per key, in any order.
 * @returns The 64-byte schnorr signature.
 */
export function aggregatePartialSignatures(session: SignSession, partialSignatures: Uint8Array[]): Uint8Array {
    const { orderedPublicKeys, aggregatedNonce, message } = session;
    assertTwoDistinctKeys("orderedPublicKeys", orderedPublicKeys);
    assertBytes("aggregatedNonce", aggregatedNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("message", message, MESSAGE_DIGEST_LENGTH);
    if (!Array.isArray(partialSignatures) || partialSignatures.length !== MUSIG_PARTICIPANTS) {
        throw new TypeError(`partialSignatures must be exactly ${MUSIG_PARTICIPANTS} partial signatures`);
    }
    for (const [index, partialSignature] of partialSignatures.entries()) {
        assertBytes(`partialSignatures[${index}]`, partialSignature, PARTIAL_SIGNATURE_LENGTH);
    }
    const signature = new Session(aggregatedNonce, orderedPublicKeys, message).partialSigAgg(partialSignatures);
    assertBytes("signature", signature, SCHNORR_SIGNATURE_LENGTH);
    if (!schnorr.verify(signature, message, keyAggExport(keyAggregate(orderedPublicKeys)))) {
        throw new TypeError("the partial signatures do not aggregate into a signature the aggregated key accepts");
    }
    return signature;
}

/**
 * Regenerates the deterministic nonce pair of one signing slot.
 * @param keys The channel's secrets.
 * @param commitmentNumber The commitment number.
 * @param context The signature the nonce is for.
 * @returns The BIP-327 nonce pair.
 */
function generateNonces(keys: FiberChannelKeys, commitmentNumber: number, context: NonceContext) {
    const nonceSeed = deriveNonceSeed(keys, commitmentNumber, context);
    return nonceGen(pubkeyOf(keys.fundingKey), keys.fundingKey, undefined, undefined, undefined, nonceSeed);
}

/**
 * Asserts that a session's key list is two distinct keys, one of them the channel's funding key.
 * @param keys The channel's secrets.
 * @param session The session.
 * @returns The position of the channel's funding key in the list.
 */
function assertCosignerKeys(keys: FiberChannelKeys, session: Pick<SignSession, "orderedPublicKeys">): number {
    const [firstKey, secondKey] = assertTwoDistinctKeys("orderedPublicKeys", session.orderedPublicKeys);
    const fundingPubkey = pubkeyOf(keys.fundingKey);
    if (equalBytes(firstKey, fundingPubkey)) return 0;
    if (equalBytes(secondKey, fundingPubkey)) return 1;
    throw new TypeError("orderedPublicKeys must include the channel funding public key");
}
