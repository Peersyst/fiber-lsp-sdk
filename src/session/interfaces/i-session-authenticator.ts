export interface ISessionAuthenticator {
    readonly publicKey: Uint8Array;
    /**
     * Signs a session challenge.
     * @param challenge The bridge's 32-byte challenge.
     * @returns The 64-byte BIP-340 signature.
     */
    signChallenge(challenge: Uint8Array): Uint8Array;
}
