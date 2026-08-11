import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import type { Script, ShutdownTxInput } from "../../../src/digest/digest.types";
import { computeShutdownTxDigest } from "../../../src/digest/shutdown-tx";
import { ckbBlake2b } from "../../../src/common/utils/ckb-hash.utils";
import { compareBytes } from "../../../src/common/utils/bytes.utils";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));

const remoteFundingPubkey = pubkeyOf(new Uint8Array(32).fill(0x33));

const LOCAL_CLOSE: Script = { codeHash: hexToBytes("cc".repeat(32)), hashType: "type", args: hexToBytes("dd".repeat(20)) };
const REMOTE_CLOSE: Script = { codeHash: hexToBytes("ee".repeat(32)), hashType: "data1", args: hexToBytes("ff".repeat(32)) };

const BASE_INPUT: ShutdownTxInput = {
    fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf0), index: 0 },
    remoteFundingPubkey,
    localCloseScript: LOCAL_CLOSE,
    remoteCloseScript: REMOTE_CLOSE,
    localFeeRate: 1000n,
    remoteFeeRate: 2143n,
    cellDepsCount: 2,
    udtTypeScript: null,
    toLocalShannons: 62_000_000_000n,
    toRemoteShannons: 18_500_000_000n,
    localReservedCkbShannons: 4_200_000_000n,
    remoteReservedCkbShannons: 6_300_000_000n,
};

const baseDigest = bytesToHex(computeShutdownTxDigest(channelKeys, BASE_INPUT));

function digestOf(overrides: Partial<ShutdownTxInput>): string {
    return bytesToHex(computeShutdownTxDigest(channelKeys, { ...BASE_INPUT, ...overrides }));
}

describe("computeShutdownTxDigest", () => {
    it("returns a deterministic 32-byte digest", () => {
        expect(computeShutdownTxDigest(channelKeys, BASE_INPUT)).toHaveLength(32);
        expect(digestOf({})).toBe(baseDigest);
    });

    it.each<[keyof ShutdownTxInput, Partial<ShutdownTxInput>]>([
        ["fundingOutPoint", { fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf1), index: 0 } }],
        ["localCloseScript", { localCloseScript: { ...LOCAL_CLOSE, args: hexToBytes("dd".repeat(21)) } }],
        ["remoteCloseScript", { remoteCloseScript: { ...REMOTE_CLOSE, hashType: "type" } }],
        ["localFeeRate", { localFeeRate: 2000n }],
        ["remoteFeeRate", { remoteFeeRate: 4286n }],
        ["cellDepsCount", { cellDepsCount: 3 }],
        ["toLocalShannons", { toLocalShannons: 62_000_000_001n }],
        ["toRemoteShannons", { toRemoteShannons: 18_500_000_001n }],
        ["localReservedCkbShannons", { localReservedCkbShannons: 4_200_000_001n }],
        ["remoteReservedCkbShannons", { remoteReservedCkbShannons: 6_300_000_001n }],
        ["udtTypeScript", { udtTypeScript: { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: new Uint8Array(0) } }],
    ])("commits to %s", (_, overrides) => {
        expect(digestOf(overrides)).not.toBe(baseDigest);
    });

    it("commits to which side owns which close script, beyond the pubkey-sorted output order", () => {
        expect(digestOf({ localCloseScript: REMOTE_CLOSE, remoteCloseScript: LOCAL_CLOSE })).not.toBe(baseDigest);
    });

    // The funding pubkeys never appear in the shutdown tx; they only decide the output order. A remote key on the other
    // side of ours must flip the outputs, and one on the same side must leave the digest byte-identical.
    it("orders the outputs by the funding-pubkey sort alone", () => {
        const localPubkey = pubkeyOf(channelKeys.fundingKey);
        const localFirstInBase = compareBytes(localPubkey, remoteFundingPubkey) <= 0;
        const candidates = Array.from({ length: 256 }, (_, at) => pubkeyOf(ckbBlake2b(Uint8Array.of(at))));
        const sortsLikeBase = (candidate: Uint8Array): boolean => compareBytes(localPubkey, candidate) <= 0 === localFirstInBase;
        const sameSide = candidates.find(sortsLikeBase) as Uint8Array;
        const otherSide = candidates.find((candidate) => !sortsLikeBase(candidate)) as Uint8Array;
        expect(digestOf({ remoteFundingPubkey: sameSide })).toBe(baseDigest);
        expect(digestOf({ remoteFundingPubkey: otherSide })).not.toBe(baseDigest);
    });

    it("refuses a fee either side cannot cover", () => {
        expect(() => digestOf({ localFeeRate: (1n << 63n) / 100n })).toThrow(RangeError);
        expect(() => digestOf({ remoteFeeRate: (1n << 63n) / 100n })).toThrow(RangeError);
    });

    it("refuses malformed inputs, one field at a time", () => {
        expect(() => digestOf({ remoteFundingPubkey: new Uint8Array(32) })).toThrow(TypeError);
        expect(() => digestOf({ localFeeRate: -1n })).toThrow(RangeError);
        expect(() => digestOf({ cellDepsCount: 256 })).toThrow(RangeError);
        expect(() => digestOf({ toLocalShannons: -1n })).toThrow(RangeError);
        expect(() => digestOf({ remoteReservedCkbShannons: 1n << 64n })).toThrow(RangeError);
        expect(() => digestOf({ localCloseScript: { ...LOCAL_CLOSE, codeHash: new Uint8Array(31) } })).toThrow(TypeError);
        expect(() => digestOf({ fundingOutPoint: { txHash: new Uint8Array(32), index: -1 } })).toThrow(RangeError);
    });
});
