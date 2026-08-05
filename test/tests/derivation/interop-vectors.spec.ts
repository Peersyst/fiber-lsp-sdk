import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { MAX_ACCOUNT_INDEX, MAX_CHANNEL_INDEX, MAX_COMMITMENT_NUMBER, NONCE_CONTEXTS } from "../../../src/derivation/derivation.constants";
import type { FiberChannelKeys } from "../../../src/derivation/derivation.types";
import { deriveChannelSeed, deriveNonceSeed, deriveWalletIdentityKey } from "../../../src/derivation/device-scheme";
import {
    deriveChannelKeys,
    derivePrivateKey,
    derivePublicKey,
    deriveTlcKey,
    getCommitmentPoint,
    getCommitmentSecret,
    pubkeyOf,
} from "../../../src/derivation/fiber-scheme";
import { deriveMasterSeed } from "../../../src/derivation/master-seed";
import { ckbBlake2b } from "../../../src/derivation/utils/ckb-hash.utils";
import { loadInteropVectors, type ChannelKeysVector } from "../../utils/interop-vectors";

function expectChannelKeys(keys: FiberChannelKeys, expected: ChannelKeysVector): void {
    expect(bytesToHex(keys.fundingKey)).toBe(expected.funding_key);
    expect(bytesToHex(keys.tlcBaseKey)).toBe(expected.tlc_base_key);
    expect(bytesToHex(keys.musig2BaseNonce)).toBe(expected.musig2_base_nonce);
    expect(bytesToHex(keys.commitmentSeed)).toBe(expected.commitment_seed);
    expect(bytesToHex(pubkeyOf(keys.fundingKey))).toBe(expected.funding_pubkey);
    expect(bytesToHex(pubkeyOf(keys.tlcBaseKey))).toBe(expected.tlc_base_pubkey);
}

const vectors = loadInteropVectors();

describe("cross-implementation vectors", () => {
    it("declares the scheme and the fiber release they were generated for", () => {
        expect(vectors.scheme_version).toBe(1);
        expect(vectors.fiber_ref).toBe("b71a61c3");
    });

    it("covers the boundaries of every input range", () => {
        expect(vectors.hashes.length).toBeGreaterThanOrEqual(4);
        expect(vectors.fiber_scheme.commitments.map((commitment) => commitment.n)).toEqual(
            expect.arrayContaining([0, 1, MAX_COMMITMENT_NUMBER]),
        );
        expect(vectors.sdk_scheme.channel_seeds.map((entry) => entry.channel_index)).toEqual(
            expect.arrayContaining([0, MAX_CHANNEL_INDEX]),
        );
        expect(vectors.sdk_scheme.master_seeds.map((entry) => entry.account_index)).toEqual(expect.arrayContaining([0, MAX_ACCOUNT_INDEX]));
        expect(new Set(vectors.sdk_scheme.channel.nonce_seeds.map((entry) => entry.context))).toEqual(new Set(NONCE_CONTEXTS));
    });

    describe("CKB hashing", () => {
        for (const vector of vectors.hashes) {
            it(`matches the "${vector.label}" digest`, () => {
                expect(bytesToHex(ckbBlake2b(...vector.chunks.map((chunk) => hexToBytes(chunk))))).toBe(vector.digest);
            });
        }
    });

    describe("fiber scheme", () => {
        const keys = deriveChannelKeys(hexToBytes(vectors.fiber_scheme.channel_seed));

        it("derives the channel keys", () => {
            expectChannelKeys(keys, vectors.fiber_scheme.channel_keys);
        });

        for (const commitment of vectors.fiber_scheme.commitments) {
            describe(`commitment ${commitment.n}`, () => {
                it("derives the commitment secret and point", () => {
                    expect(bytesToHex(getCommitmentSecret(keys.commitmentSeed, commitment.n))).toBe(commitment.secret);
                    expect(bytesToHex(getCommitmentPoint(keys.commitmentSeed, commitment.n))).toBe(commitment.point);
                });

                it("derives the TLC key through the private and the public path", () => {
                    const point = hexToBytes(commitment.point);
                    expect(bytesToHex(deriveTlcKey(keys, commitment.n))).toBe(commitment.tlc_privkey);
                    expect(bytesToHex(pubkeyOf(deriveTlcKey(keys, commitment.n)))).toBe(commitment.tlc_pubkey);
                    expect(bytesToHex(derivePublicKey(pubkeyOf(keys.tlcBaseKey), point))).toBe(commitment.tlc_pubkey);
                });

                it("derives the musig2 nonce secret fiber would derive", () => {
                    const point = hexToBytes(commitment.point);
                    expect(bytesToHex(derivePrivateKey(keys.musig2BaseNonce, point))).toBe(commitment.musig2_nonce_seckey);
                });
            });
        }
    });

    describe("SDK scheme", () => {
        const masterSeed = hexToBytes(vectors.sdk_scheme.master_seed);

        for (const entry of vectors.sdk_scheme.master_seeds) {
            it(`derives the master seed at ${entry.path}`, () => {
                expect(bytesToHex(deriveMasterSeed(hexToBytes(vectors.sdk_scheme.bip39_seed), entry.account_index))).toBe(
                    entry.master_seed,
                );
            });
        }

        it("derives the wallet identity key", () => {
            expect(bytesToHex(deriveWalletIdentityKey(masterSeed))).toBe(vectors.sdk_scheme.wallet_identity_key);
        });

        for (const entry of vectors.sdk_scheme.channel_seeds) {
            it(`derives the seed of channel ${entry.channel_index}`, () => {
                expect(bytesToHex(deriveChannelSeed(masterSeed, entry.channel_index))).toBe(entry.seed);
            });
        }

        describe(`channel ${vectors.sdk_scheme.channel.channel_index}`, () => {
            const channelSeed = deriveChannelSeed(masterSeed, vectors.sdk_scheme.channel.channel_index);
            const keys = deriveChannelKeys(channelSeed);

            it("chains the master seed into fiber's channel keys", () => {
                expect(bytesToHex(channelSeed)).toBe(vectors.sdk_scheme.channel.seed);
                expectChannelKeys(keys, vectors.sdk_scheme.channel.channel_keys);
            });

            for (const entry of vectors.sdk_scheme.channel.nonce_seeds) {
                it(`derives the ${entry.context} nonce seed for commitment ${entry.commitment_number}`, () => {
                    expect(bytesToHex(deriveNonceSeed(keys, entry.commitment_number, entry.context))).toBe(entry.seed);
                });
            }
        });
    });
});
