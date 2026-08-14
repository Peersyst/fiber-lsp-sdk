import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import {
    COMPRESSED_POINT_LENGTH,
    MESSAGE_DIGEST_LENGTH,
    MUSIG_PARTICIPANTS,
    PUBLIC_NONCE_LENGTH,
    assertBytes,
    ckbBlake2b,
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
export function assertSessionShape(session: SignSession): [Uint8Array, Uint8Array] {
    if (!Array.isArray(session.orderedPublicKeys) || session.orderedPublicKeys.length !== MUSIG_PARTICIPANTS) {
        throw new TypeError(`session.orderedPublicKeys must be exactly ${MUSIG_PARTICIPANTS} public keys`);
    }
    const [firstKey, secondKey] = session.orderedPublicKeys;
    assertBytes("session.orderedPublicKeys[0]", firstKey, COMPRESSED_POINT_LENGTH);
    assertBytes("session.orderedPublicKeys[1]", secondKey, COMPRESSED_POINT_LENGTH);
    assertBytes("session.aggregatedNonce", session.aggregatedNonce, PUBLIC_NONCE_LENGTH);
    assertBytes("session.message", session.message, MESSAGE_DIGEST_LENGTH);
    if (equalBytes(firstKey, secondKey)) {
        throw new TypeError("session.orderedPublicKeys must be two distinct public keys");
    }
    return [firstKey, secondKey];
}

/**
 * Asserts that a session is one this channel can sign: well-shaped, and aggregating the channel's own funding key.
 * @param keys The channel's four secrets.
 * @param session Session to check.
 */
export function assertSignSession(keys: FiberChannelKeys, session: SignSession): void {
    const publicKeys = assertSessionShape(session);
    const fundingPubkey = pubkeyOf(keys.fundingKey);
    if (!publicKeys.some((key) => equalBytes(key, fundingPubkey))) {
        throw new TypeError("session.orderedPublicKeys must include the channel funding public key");
    }
}

/**
 * Commits to everything a slot's signature answers: the ordered key list, the aggregated nonce and the message.
 * @param session Session to commit to.
 * @returns The 32-byte commitment as lowercase hex, the value the sign-once registry stores.
 */
export function buildSessionCommitment(session: SignSession): string {
    const [firstKey, secondKey] = assertSessionShape(session);
    return bytesToHex(ckbBlake2b(LABEL, firstKey, secondKey, session.aggregatedNonce, session.message));
}
