import { secp256k1 } from "@noble/curves/secp256k1.js";
import { concatBytes } from "@noble/hashes/utils.js";
import type { Transaction } from "../common";
import { RECOVERABLE_ECDSA_SIGNATURE_LENGTH, assertBytes } from "../common";
import type { FiberChannelKeys } from "../derivation";
import { deriveTlcKey } from "../derivation";
import { computeTxMessage } from "../digest";
import type { WatchtowerKeyPurpose } from "../policy";
import { assertWatchtowerKeyPurpose } from "../policy";

/**
 * Signs a watchtower spend as fiber's `sign_onchain` does: recoverable ECDSA over the tx message, the recovery id last.
 * @param keys The channel's four secrets.
 * @param purpose The key the spend's unlock needs.
 * @param transaction The spend as fiber's watchtower built it.
 * @returns The 65-byte signature, `r`, `s` and the recovery id.
 */
export function signOnchain(keys: FiberChannelKeys, purpose: WatchtowerKeyPurpose, transaction: Transaction): Uint8Array {
    assertWatchtowerKeyPurpose("purpose", purpose);
    const secretKey = purpose.kind === "settlement" ? keys.tlcBaseKey : deriveTlcKey(keys, purpose.commitmentNumber);
    // As rust-secp256k1's `sign_ecdsa_recoverable`: no prehash, RFC 6979 without extra entropy, low-S.
    const recovered = secp256k1.sign(computeTxMessage(transaction), secretKey, {
        prehash: false,
        lowS: true,
        extraEntropy: false,
        format: "recovered",
    });
    assertBytes("signature", recovered, RECOVERABLE_ECDSA_SIGNATURE_LENGTH);
    // Noble writes the recovery id first; fiber's `serialize_compact` writes it after `r` and `s`.
    return concatBytes(recovered.subarray(1), recovered.subarray(0, 1));
}
