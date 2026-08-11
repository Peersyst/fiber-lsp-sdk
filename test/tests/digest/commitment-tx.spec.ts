import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import { buildCommitmentLockArgs, computeCommitmentTxDigest } from "../../../src/digest/commitment-tx";
import { blake160 } from "../../../src/common/utils/ckb-hash.utils";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
import type { CommitmentTxInput, SettlementTlc } from "../../../src/digest/digest.types";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));

const remoteFundingPubkey = pubkeyOf(new Uint8Array(32).fill(0x33));
const remoteTlcBasePubkey = pubkeyOf(new Uint8Array(32).fill(0x66));

const TLC: SettlementTlc = {
    id: 1,
    direction: "offered",
    hashAlgorithm: "ckb-hash",
    amountShannons: 1_000_000_000n,
    paymentHash: new Uint8Array(32).fill(0xa1),
    expiryMs: 1_723_257_890_123n,
    createdAtRemoteCommitmentNumber: 2,
    remoteCommitmentPoint: pubkeyOf(new Uint8Array(32).fill(0x55)),
};

const BASE_INPUT: CommitmentTxInput = {
    forRemote: true,
    fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf0), index: 0 },
    remoteFundingPubkey,
    remoteTlcBasePubkey,
    commitmentNumber: 11,
    commitmentDelayEpoch: (1n << 40n) | 1n,
    commitmentFeeRate: 1000n,
    cellDepsCount: 2,
    udtTypeScript: null,
    toLocalShannons: 62_000_000_000n,
    toRemoteShannons: 18_500_000_000n,
    settlementLocalShannons: 62_000_000_000n,
    settlementRemoteShannons: 18_500_000_000n,
    localReservedCkbShannons: 4_200_000_000n,
    remoteReservedCkbShannons: 6_300_000_000n,
    tlcs: [],
    commitmentLock: COMMITMENT_LOCK_TESTNET,
};

const UDT_INPUT: CommitmentTxInput = {
    ...BASE_INPUT,
    cellDepsCount: 3,
    udtTypeScript: { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: hexToBytes("bb".repeat(32)) },
    toLocalShannons: 500_000_000_000_000_000_000n,
    toRemoteShannons: 300_000_000_000_000_000_000n,
    settlementLocalShannons: 500_000_000_000_000_000_000n,
    settlementRemoteShannons: 300_000_000_000_000_000_000n,
};

const baseDigest = bytesToHex(computeCommitmentTxDigest(channelKeys, BASE_INPUT));

function digestOf(overrides: Partial<CommitmentTxInput>): string {
    return bytesToHex(computeCommitmentTxDigest(channelKeys, { ...BASE_INPUT, ...overrides }));
}

describe("buildCommitmentLockArgs", () => {
    const XONLY = new Uint8Array(32).fill(0x11);
    const WITNESS = new Uint8Array(73);

    it("lays out the 57 bytes: key hash, delay since, big-endian version, witness hash, trailing zero", () => {
        const args = buildCommitmentLockArgs(XONLY, (1n << 40n) | 1n, 281474976710655, WITNESS);
        expect(args).toHaveLength(57);
        expect(bytesToHex(args.slice(0, 20))).toBe(bytesToHex(blake160(XONLY)));
        // 0xA000_0100_0000_0001 little-endian: the relative epoch flags land in the last byte.
        expect(bytesToHex(args.slice(20, 28))).toBe("01000000000100a0");
        expect(bytesToHex(args.slice(28, 36))).toBe("0000ffffffffffff");
        expect(bytesToHex(args.slice(36, 56))).toBe(bytesToHex(blake160(WITNESS)));
        expect(args[56]).toBe(0x00);
    });

    it("refuses a delay or version out of range", () => {
        expect(() => buildCommitmentLockArgs(XONLY, 1n << 56n, 0, WITNESS)).toThrow(RangeError);
        expect(() => buildCommitmentLockArgs(XONLY, 0n, 2 ** 48, WITNESS)).toThrow(RangeError);
    });
});

describe("computeCommitmentTxDigest", () => {
    it("returns a deterministic 32-byte digest", () => {
        expect(computeCommitmentTxDigest(channelKeys, BASE_INPUT)).toHaveLength(32);
        expect(digestOf({})).toBe(baseDigest);
    });

    it.each<[keyof CommitmentTxInput, Partial<CommitmentTxInput>]>([
        ["forRemote", { forRemote: false }],
        ["fundingOutPoint", { fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf1), index: 0 } }],
        ["fundingOutPoint", { fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf0), index: 1 } }],
        ["remoteFundingPubkey", { remoteFundingPubkey: pubkeyOf(new Uint8Array(32).fill(0x34)) }],
        ["remoteTlcBasePubkey", { remoteTlcBasePubkey: pubkeyOf(new Uint8Array(32).fill(0x67)) }],
        ["commitmentNumber", { commitmentNumber: 12 }],
        ["commitmentDelayEpoch", { commitmentDelayEpoch: (2n << 40n) | 1n }],
        ["commitmentFeeRate", { commitmentFeeRate: 2000n }],
        ["cellDepsCount", { cellDepsCount: 3 }],
        ["toLocalShannons", { toLocalShannons: 62_000_000_001n }],
        ["toRemoteShannons", { toRemoteShannons: 18_500_000_001n }],
        ["settlementLocalShannons", { settlementLocalShannons: 61_999_999_999n }],
        ["settlementRemoteShannons", { settlementRemoteShannons: 18_499_999_999n }],
        ["localReservedCkbShannons", { localReservedCkbShannons: 4_200_000_001n }],
        ["remoteReservedCkbShannons", { remoteReservedCkbShannons: 6_300_000_001n }],
        ["tlcs", { tlcs: [TLC] }],
        ["commitmentLock", { commitmentLock: { ...COMMITMENT_LOCK_TESTNET, hashType: "data" } }],
        ["udtTypeScript", { udtTypeScript: UDT_INPUT.udtTypeScript }],
    ])("commits to %s", (_, overrides) => {
        expect(digestOf(overrides)).not.toBe(baseDigest);
    });

    it("digests the UDT variant differently and deterministically", () => {
        const udtDigest = bytesToHex(computeCommitmentTxDigest(channelKeys, UDT_INPUT));
        expect(udtDigest).not.toBe(baseDigest);
        expect(bytesToHex(computeCommitmentTxDigest(channelKeys, UDT_INPUT))).toBe(udtDigest);
    });

    it("refuses a fee the capacity cannot cover", () => {
        expect(() => digestOf({ commitmentFeeRate: (1n << 63n) / 456n })).toThrow(RangeError);
    });

    it("refuses malformed inputs, one field at a time", () => {
        expect(() => digestOf({ remoteFundingPubkey: new Uint8Array(32) })).toThrow(TypeError);
        expect(() => digestOf({ remoteTlcBasePubkey: new Uint8Array(34) })).toThrow(TypeError);
        expect(() => digestOf({ commitmentNumber: 2 ** 48 })).toThrow(RangeError);
        expect(() => digestOf({ commitmentDelayEpoch: 1n << 56n })).toThrow(RangeError);
        expect(() => digestOf({ commitmentFeeRate: -1n })).toThrow(RangeError);
        expect(() => digestOf({ cellDepsCount: 256 })).toThrow(RangeError);
        expect(() => digestOf({ toLocalShannons: -1n })).toThrow(RangeError);
        expect(() => digestOf({ toRemoteShannons: 1n << 128n })).toThrow(RangeError);
        expect(() => digestOf({ settlementLocalShannons: -1n })).toThrow(RangeError);
        expect(() => digestOf({ localReservedCkbShannons: 1n << 64n })).toThrow(RangeError);
        expect(() => digestOf({ fundingOutPoint: { txHash: new Uint8Array(31), index: 0 } })).toThrow(TypeError);
    });
});
