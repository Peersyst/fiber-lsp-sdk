import { utf8ToBytes } from "@noble/hashes/utils.js";
import { assertBytes, ckbBlake2b } from "../../common";
import { CHALLENGE_LENGTH, SESSION_CHALLENGE_LABEL } from "../protocol.constants";

const LABEL = utf8ToBytes(SESSION_CHALLENGE_LABEL);

/**
 * Hashes a session challenge under the protocol's label: what the identity key signs, and what the bridge verifies.
 * @param challenge The 32 challenge bytes the bridge sent.
 * @returns The 32-byte digest.
 */
export function sessionChallengeDigest(challenge: Uint8Array): Uint8Array {
    assertBytes("challenge", challenge, CHALLENGE_LENGTH);
    return ckbBlake2b(LABEL, challenge);
}
