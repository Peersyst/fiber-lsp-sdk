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
