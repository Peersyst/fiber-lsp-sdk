import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { CHALLENGE_LENGTH, sessionChallengeDigest } from "../../../src/protocol";
import { WalletIdentity } from "../../../src/signer";
import { loadInteropVectors } from "../../utils/interop-vectors";

const vectors = loadInteropVectors();
const MASTER_SEED = hexToBytes(vectors.sdk_scheme.master_seed);
const CHALLENGE = new Uint8Array(CHALLENGE_LENGTH).fill(0x5c);

const identity = new WalletIdentity(MASTER_SEED);

describe("WalletIdentity", () => {
    describe("publicKey", () => {
        it("is the x-only public key of the wallet identity key of the vectors", () => {
            expect(identity.publicKey).toHaveLength(32);
            expect(bytesToHex(identity.publicKey)).toBe(
                bytesToHex(schnorr.getPublicKey(hexToBytes(vectors.sdk_scheme.wallet_identity_key))),
            );
        });

        // The bridge pins this key per account across sessions: a change locks every restored wallet out of its LSP.
        it("is pinned for the vector master seed", () => {
            expect(bytesToHex(identity.publicKey)).toBe("8dd0502b955500a40aa41114374cdc96ed2c34e85e1473f23ae80cddb0afcb26");
        });

        it("is the same on every device restored from the seed", () => {
            expect(bytesToHex(new WalletIdentity(Uint8Array.from(MASTER_SEED)).publicKey)).toBe(bytesToHex(identity.publicKey));
        });

        it("differs per seed", () => {
            expect(bytesToHex(new WalletIdentity(new Uint8Array(32).fill(0x42)).publicKey)).not.toBe(bytesToHex(identity.publicKey));
        });
    });

    it("keeps its key when the host discards the seed buffer", () => {
        const seed = Uint8Array.from(MASTER_SEED);
        const discarded = new WalletIdentity(seed);
        seed.fill(0);
        expect(bytesToHex(discarded.publicKey)).toBe(bytesToHex(identity.publicKey));
        expect(bytesToHex(discarded.signChallenge(CHALLENGE))).toBe(bytesToHex(identity.signChallenge(CHALLENGE)));
    });

    it.each([31, 33])("rejects a master seed of %i bytes", (length) => {
        expect(() => new WalletIdentity(new Uint8Array(length))).toThrow(TypeError);
    });

    describe("signChallenge", () => {
        it("verifies under the domain-separated digest with the x-only key", () => {
            const signature = identity.signChallenge(CHALLENGE);
            expect(signature).toHaveLength(64);
            expect(schnorr.verify(signature, sessionChallengeDigest(CHALLENGE), identity.publicKey)).toBe(true);
        });

        it("never signs the bare challenge", () => {
            expect(schnorr.verify(identity.signChallenge(CHALLENGE), CHALLENGE, identity.publicKey)).toBe(false);
        });

        it("is deterministic, and pinned for a fixed challenge", () => {
            const signature = bytesToHex(identity.signChallenge(CHALLENGE));
            expect(bytesToHex(identity.signChallenge(CHALLENGE))).toBe(signature);
            expect(signature).toBe(
                "e36f699ad510624705117a3af8f9354e02b79737e4aaa9d90c9c01db60812d2f95f1a4213a693258a7c59a948f0b8e42b107d708430998bb7976fc4239c55769",
            );
        });

        it("is distinct per challenge", () => {
            const other = Uint8Array.from(CHALLENGE).fill(0x5d, 0, 1);
            expect(bytesToHex(identity.signChallenge(other))).not.toBe(bytesToHex(identity.signChallenge(CHALLENGE)));
        });

        it("does not verify under another identity", () => {
            const other = new WalletIdentity(new Uint8Array(32).fill(0x42));
            expect(schnorr.verify(identity.signChallenge(CHALLENGE), sessionChallengeDigest(CHALLENGE), other.publicKey)).toBe(false);
        });

        it.each([CHALLENGE_LENGTH - 1, CHALLENGE_LENGTH + 1])("rejects a challenge of %i bytes", (length) => {
            expect(() => identity.signChallenge(new Uint8Array(length))).toThrow(TypeError);
        });
    });
});
