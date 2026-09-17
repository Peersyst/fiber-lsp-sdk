import type { NONCE_CONTEXTS } from "./derivation.constants";

/**
 * The four secrets fiber's `InMemorySigner` holds for one channel.
 */
export type FiberChannelKeys = {
    fundingKey: Uint8Array;
    tlcBaseKey: Uint8Array;
    musig2BaseNonce: Uint8Array;
    /**
     * Root of the commitment secret chain: the secret of commitment number 0.
     */
    commitmentSeed: Uint8Array;
};

export type NonceContext = (typeof NONCE_CONTEXTS)[number];

/**
 * The public halves of the channel's base keys, registered with the node at channel open.
 */
export type BasePublicKeys = {
    fundingPubkey: Uint8Array;
    tlcBasePubkey: Uint8Array;
};
