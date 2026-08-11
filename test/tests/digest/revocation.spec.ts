import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
import type { RevocationInput, Script } from "../../../src/digest/digest.types";
import { computeRevocationDigest } from "../../../src/digest/revocation";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));

const remoteFundingPubkey = pubkeyOf(new Uint8Array(32).fill(0x33));

const PAYOUT_SCRIPT: Script = { codeHash: hexToBytes("ee".repeat(32)), hashType: "data1", args: hexToBytes("ff".repeat(32)) };

const BASE_INPUT: RevocationInput = {
    forRemote: false,
    revokedCommitmentNumber: 4,
    payoutScript: PAYOUT_SCRIPT,
    remoteFundingPubkey,
    commitmentDelayEpoch: (1n << 40n) | 1n,
    commitmentFeeRate: 1000n,
    cellDepsCount: 2,
    udtTypeScript: null,
    toLocalShannons: 62_000_000_000n,
    toRemoteShannons: 18_500_000_000n,
    localReservedCkbShannons: 4_200_000_000n,
    remoteReservedCkbShannons: 6_300_000_000n,
    commitmentLock: COMMITMENT_LOCK_TESTNET,
};

const baseDigest = bytesToHex(computeRevocationDigest(channelKeys, BASE_INPUT));

function digestOf(overrides: Partial<RevocationInput>): string {
    return bytesToHex(computeRevocationDigest(channelKeys, { ...BASE_INPUT, ...overrides }));
}

describe("computeRevocationDigest", () => {
    it("returns a deterministic 32-byte digest", () => {
        expect(computeRevocationDigest(channelKeys, BASE_INPUT)).toHaveLength(32);
        expect(digestOf({})).toBe(baseDigest);
    });

    // The revocation aggregation is role-ordered, so flipping the direction must move the x-only key in the args.
    it("commits to the direction through the role-ordered key aggregation", () => {
        expect(digestOf({ forRemote: true })).not.toBe(baseDigest);
    });

    it.each<[keyof RevocationInput, Partial<RevocationInput>]>([
        ["revokedCommitmentNumber", { revokedCommitmentNumber: 5 }],
        ["payoutScript", { payoutScript: { ...PAYOUT_SCRIPT, hashType: "type" } }],
        ["remoteFundingPubkey", { remoteFundingPubkey: pubkeyOf(new Uint8Array(32).fill(0x34)) }],
        ["commitmentDelayEpoch", { commitmentDelayEpoch: (2n << 40n) | 1n }],
        ["commitmentFeeRate", { commitmentFeeRate: 2000n }],
        ["cellDepsCount", { cellDepsCount: 3 }],
        ["toLocalShannons", { toLocalShannons: 62_000_000_001n }],
        ["toRemoteShannons", { toRemoteShannons: 18_500_000_001n }],
        ["localReservedCkbShannons", { localReservedCkbShannons: 4_200_000_001n }],
        ["remoteReservedCkbShannons", { remoteReservedCkbShannons: 6_300_000_001n }],
        ["udtTypeScript", { udtTypeScript: { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: new Uint8Array(0) } }],
    ])("commits to %s", (_, overrides) => {
        expect(digestOf(overrides)).not.toBe(baseDigest);
    });

    // The commitment lock never appears in the revocation message; it only sizes the fee mock, where its args are zeroed
    // at a fixed 57 bytes, so a different code hash or hash type must leave the digest untouched.
    it("does not commit to the commitment lock's content", () => {
        expect(digestOf({ commitmentLock: { ...COMMITMENT_LOCK_TESTNET, hashType: "data" } })).toBe(baseDigest);
        expect(digestOf({ commitmentLock: { ...COMMITMENT_LOCK_TESTNET, codeHash: new Uint8Array(32) } })).toBe(baseDigest);
    });

    it("refuses a fee the capacity cannot cover", () => {
        expect(() => digestOf({ commitmentFeeRate: (1n << 63n) / 456n })).toThrow(RangeError);
    });

    it("refuses malformed inputs, one field at a time", () => {
        expect(() => digestOf({ remoteFundingPubkey: new Uint8Array(32) })).toThrow(TypeError);
        expect(() => digestOf({ revokedCommitmentNumber: 2 ** 48 })).toThrow(RangeError);
        expect(() => digestOf({ commitmentDelayEpoch: 1n << 56n })).toThrow(RangeError);
        expect(() => digestOf({ commitmentFeeRate: -1n })).toThrow(RangeError);
        expect(() => digestOf({ toLocalShannons: 1n << 128n })).toThrow(RangeError);
        expect(() => digestOf({ localReservedCkbShannons: -1n })).toThrow(RangeError);
        expect(() => digestOf({ payoutScript: { ...PAYOUT_SCRIPT, codeHash: new Uint8Array(31) } })).toThrow(TypeError);
    });
});
