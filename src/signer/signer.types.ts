import type { NonceContext } from "../derivation";

/**
 * The public halves of the channel's base keys, registered with the node at channel open.
 */
export type BasePublicKeys = {
    fundingPubkey: Uint8Array;
    tlcBasePubkey: Uint8Array;
};

/**
 * One partial-signature request over an already-computed 32-byte digest.
 */
export type PartialSignRequest = {
    /**
     * The 2-of-2 key list exactly as the node sent it; the SDK never sorts or reorders it.
     */
    orderedPublicKeys: Uint8Array[];
    /**
     * The 66-byte aggregated public nonce the node computed for this slot.
     */
    aggregatedNonce: Uint8Array;
    /**
     * The 32-byte digest to sign, opaque to the engine until the policy layer recomputes it.
     */
    message: Uint8Array;
    commitmentNumber: number;
    context: NonceContext;
};
