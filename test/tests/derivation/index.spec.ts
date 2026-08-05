import * as derivation from "../../../src/derivation";

describe("derivation module surface", () => {
    it("exports the derivations the rest of the SDK consumes", () => {
        expect(Object.keys(derivation).sort()).toEqual(
            [
                "BIP39_SEED_LENGTH",
                "DERIVATION_SCHEME_VERSION",
                "MASTER_SEED_LENGTH",
                "MAX_ACCOUNT_INDEX",
                "MAX_CHANNEL_INDEX",
                "MAX_COMMITMENT_NUMBER",
                "NONCE_CONTEXTS",
                "ckbBlake2b",
                "deriveChannelKeys",
                "deriveChannelSeed",
                "deriveWalletIdentityKey",
                "deriveMasterSeed",
                "deriveNonceSeed",
                "derivePrivateKey",
                "derivePublicKey",
                "deriveTlcKey",
                "getCommitmentPoint",
                "getCommitmentSecret",
                "pubkeyOf",
            ].sort(),
        );
    });
});
