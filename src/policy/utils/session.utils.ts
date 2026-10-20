import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import {
    MESSAGE_DIGEST_LENGTH,
    PUBLIC_NONCE_LENGTH,
    assertBytes,
    assertTwoDistinctKeys,
    ckbBlake2b,
    isAggregatedNonceHalf,
    isCompressedPoint,
    nonceHalves,
} from "../../common";
import type { FiberChannelKeys } from "../../derivation";
import { pubkeyOf } from "../../derivation";
import { SESSION_COMMITMENT_LABEL } from "../policy.constants";
import type { SignSession } from "../policy.types";

const LABEL = utf8ToBytes(SESSION_COMMITMENT_LABEL);

/**
 * Asserts that a session has the shape a partial signature needs, and hands back its two public keys narrowed.
 * @param session Session to check.
 * @returns The two validated 33-byte public keys, in the order the node sent them.
 */
export function assertSignSessionShape(session: SignSession): [Uint8Array, Uint8Array] {
    const publicKeys = assertTwoDistinctKeys("session.orderedPublicKeys", session.orderedPublicKeys);
    assertBytes("session.aggregatedNonce", session.aggregatedNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("session.message", session.message, MESSAGE_DIGEST_LENGTH);
    return publicKeys;
}

/**
 * Asserts that a session is one this channel can sign: well-shaped, on the curve, and aggregating the channel's own funding key.
 * @param keys The channel's four secrets.
 * @param session Session to check.
 */
export function assertSignSession(keys: FiberChannelKeys, session: SignSession): void {
    const publicKeys = assertSignSessionShape(session);
    const fundingPubkey = pubkeyOf(keys.fundingKey);
    if (!publicKeys.some((key) => equalBytes(key, fundingPubkey))) {
        throw new TypeError("session.orderedPublicKeys must include the channel funding public key");
    }
    // The engine would refuse these too, but only after the claim, leaving the slot served with nothing signed.
    if (!publicKeys.every(isCompressedPoint)) {
        throw new TypeError("session.orderedPublicKeys must be points on the curve");
    }
    if (!nonceHalves(session.aggregatedNonce).every(isAggregatedNonceHalf)) {
        throw new TypeError("session.aggregatedNonce must be two points on the curve or at infinity");
    }
}

/**
 * Commits to everything a slot's signature answers: the ordered key list, the aggregated nonce and the message.
 * @param session Session to commit to.
 * @returns The 32-byte commitment as lowercase hex, the value the sign-once registry stores.
 */
export function buildSessionCommitment(session: SignSession): string {
    const [firstKey, secondKey] = assertSignSessionShape(session);
    return bytesToHex(ckbBlake2b(LABEL, firstKey, secondKey, session.aggregatedNonce, session.message));
}
