import * as derivation from "../../../src/derivation/index.js";

describe("derivation module surface", () => {
    it("exports the derivations the rest of the SDK consumes", () => {
        expect(Object.keys(derivation).sort()).toEqual(
            [
                "DERIVATION_SCHEME_VERSION",
                "MASTER_SEED_LENGTH",
                "MAX_CHANNEL_INDEX",
                "MAX_COMMITMENT_NUMBER",
                "NONCE_CONTEXTS",
                "ckbBlake2b",
                "deriveChannelKeys",
                "deriveChannelSeed",
                "deriveWalletIdentityKey",
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
