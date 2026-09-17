import { schnorr } from "@noble/curves/secp256k1.js";
import { deriveWalletIdentityKey } from "../derivation";
import { sessionChallengeDigest } from "../protocol";

const FIXED_AUX_RAND = new Uint8Array(32);

export class WalletIdentity {
    readonly publicKey: Uint8Array;

    private readonly key: Uint8Array;

    /**
     * Derives the identity that answers the session challenge, the same on every device restored from one seed.
     * @param masterSeed The 32-byte master seed.
     */
    constructor(masterSeed: Uint8Array) {
        this.key = deriveWalletIdentityKey(masterSeed);
        this.publicKey = schnorr.getPublicKey(this.key);
    }

    /**
     * Signs a session challenge under the protocol's domain separation, never the bare bytes the bridge chose.
     * @param challenge The 32 challenge bytes the bridge sent.
     * @returns The 64-byte BIP-340 signature.
     */
    signChallenge(challenge: Uint8Array): Uint8Array {
        return schnorr.sign(sessionChallengeDigest(challenge), this.key, FIXED_AUX_RAND);
    }
}
