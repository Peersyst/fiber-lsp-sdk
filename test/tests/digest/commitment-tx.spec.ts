import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import {
    buildCommitmentLockArgs,
    computeCommitmentTxDigest,
    readCommitmentLockDelay,
    readCommitmentLockLayout,
    readCommitmentLockVersion,
} from "../../../src/digest/commitment-tx";
import { blake160 } from "../../../src/common/utils/ckb-hash.utils";
import { COMMITMENT_LOCK_LAYOUTS, COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
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
    localKeyCommitmentNumber: 2,
    remoteTlcPubkey: pubkeyOf(new Uint8Array(32).fill(0x55)),
};

// The same TLC with its payment hash changed from byte 20 on: what a legacy record leaves out and a full one binds.
const TLC_TAIL: SettlementTlc = { ...TLC, paymentHash: new Uint8Array(32).fill(0xa1).fill(0xa2, 20) };

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
    liquidCapacityShannons: 80_500_000_000n,
    settlementLocalShannons: 62_000_000_000n,
    settlementRemoteShannons: 18_500_000_000n,
    localReservedCkbShannons: 4_200_000_000n,
    remoteReservedCkbShannons: 6_300_000_000n,
    tlcs: [],
    commitmentLock: COMMITMENT_LOCK_TESTNET,
    lockLayout: "legacy",
};

const UDT_INPUT: CommitmentTxInput = {
    ...BASE_INPUT,
    cellDepsCount: 3,
    udtTypeScript: { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: hexToBytes("bb".repeat(32)) },
    liquidCapacityShannons: 800_000_000_000_000_000_000n,
    settlementLocalShannons: 500_000_000_000_000_000_000n,
    settlementRemoteShannons: 300_000_000_000_000_000_000n,
};

const baseDigest = bytesToHex(computeCommitmentTxDigest(channelKeys, BASE_INPUT));

function digestOf(overrides: Partial<CommitmentTxInput>): string {
    return bytesToHex(computeCommitmentTxDigest(channelKeys, { ...BASE_INPUT, ...overrides }));
}

const XONLY = new Uint8Array(32).fill(0x11);
const WITNESS = new Uint8Array(73);
const DELAY = (1n << 40n) | 1n;
const VERSION = 281474976710655;

describe("buildCommitmentLockArgs", () => {
    it("lays out the 57 legacy bytes: key hash, delay since, big-endian version, witness hash, trailing zero", () => {
        const args = buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, "legacy");
        expect(args).toHaveLength(57);
        expect(bytesToHex(args.slice(0, 20))).toBe(bytesToHex(blake160(XONLY)));
        // 0xA000_0100_0000_0001 little-endian: the relative epoch flags land in the last byte.
        expect(bytesToHex(args.slice(20, 28))).toBe("01000000000100a0");
        expect(bytesToHex(args.slice(28, 36))).toBe("0000ffffffffffff");
        expect(bytesToHex(args.slice(36, 56))).toBe(bytesToHex(blake160(WITNESS)));
        expect(args[56]).toBe(0x00);
    });

    it("lays out the 58 fullPaymentHash bytes: the same 56, the trailing zero, then the feature byte 0x01", () => {
        const args = buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, "fullPaymentHash");
        expect(args).toHaveLength(58);
        expect(bytesToHex(args.slice(0, 57))).toBe(bytesToHex(buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, "legacy")));
        expect(args[56]).toBe(0x00);
        expect(args[57]).toBe(0x01);
    });

    it("refuses a delay or version out of range", () => {
        expect(() => buildCommitmentLockArgs(XONLY, 1n << 56n, 0, WITNESS, "legacy")).toThrow(RangeError);
        expect(() => buildCommitmentLockArgs(XONLY, 0n, 2 ** 48, WITNESS, "legacy")).toThrow(RangeError);
    });

    it.each([undefined, null, "full_payment_hash", "Legacy", "constructor"])("refuses the layout %p", (layout) => {
        expect(() => buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, layout as never)).toThrow(
            new TypeError("lockLayout must be one of legacy, fullPaymentHash"),
        );
    });
});

describe("readCommitmentLockLayout", () => {
    it("reads 57 bytes as legacy", () => {
        expect(readCommitmentLockLayout(new Uint8Array(57).fill(0xab))).toBe("legacy");
    });

    it("reads 58 bytes ending in 0x01 as fullPaymentHash", () => {
        const args = new Uint8Array(58).fill(0xab);
        args[57] = 0x01;
        expect(readCommitmentLockLayout(args)).toBe("fullPaymentHash");
    });

    it.each(COMMITMENT_LOCK_LAYOUTS)("reads back the layout the args were built under: %s", (layout) => {
        expect(readCommitmentLockLayout(buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, layout))).toBe(layout);
    });

    it.each([
        [0, "commitment lock args must be 57 or 58 bytes, got 0"],
        [56, "commitment lock args must be 57 or 58 bytes, got 56"],
        [59, "commitment lock args must be 57 or 58 bytes, got 59"],
    ])("refuses %i bytes", (length, message) => {
        expect(() => readCommitmentLockLayout(new Uint8Array(length).fill(0xab))).toThrow(new TypeError(message));
    });

    it.each([
        [0x00, "commitment lock args of 58 bytes must end in the feature byte 0x01, got 0x00"],
        [0x02, "commitment lock args of 58 bytes must end in the feature byte 0x01, got 0x02"],
        [0xff, "commitment lock args of 58 bytes must end in the feature byte 0x01, got 0xff"],
    ])("refuses 58 bytes ending in %i", (featureByte, message) => {
        const args = new Uint8Array(58).fill(0xab);
        args[57] = featureByte;
        expect(() => readCommitmentLockLayout(args)).toThrow(new TypeError(message));
    });

    it("refuses what is not bytes", () => {
        expect(() => readCommitmentLockLayout("ab".repeat(57) as never)).toThrow(
            new TypeError("commitment lock args must be a Uint8Array"),
        );
        expect(() => readCommitmentLockLayout(Array.from(new Uint8Array(57)) as never)).toThrow(TypeError);
    });
});

// The 36 bytes a commitment lock's args and a revocation's share: key hash, delay since, big-endian version.
function lockArgsOf(length: number, delaySince: bigint, version: bigint): Uint8Array {
    const args = new Uint8Array(length).fill(0xab);
    const view = new DataView(args.buffer);
    view.setBigUint64(20, delaySince, true);
    view.setBigUint64(28, version, false);
    return args;
}

describe("readCommitmentLockDelay", () => {
    it.each(COMMITMENT_LOCK_LAYOUTS)("reads back the delay the %s args were built with", (layout) => {
        expect(readCommitmentLockDelay(buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, layout))).toBe(DELAY);
    });

    it.each([36, 57, 58])("reads the delay out of %i bytes, its relative epoch flags stripped", (length) => {
        expect(readCommitmentLockDelay(lockArgsOf(length, 0xa0ffffffffffffffn, 0n))).toBe((1n << 56n) - 1n);
        expect(readCommitmentLockDelay(lockArgsOf(length, 0xa000000000000000n, 0n))).toBe(0n);
    });

    it.each([0x00, 0x20, 0x80, 0xa1, 0xe0, 0xff])("refuses a since whose flags byte is %i, no relative epoch delay", (flags) => {
        const since = (BigInt(flags) << 56n) | 1n;
        expect(() => readCommitmentLockDelay(lockArgsOf(57, since, 0n))).toThrow(
            new TypeError(`commitment lock args must carry a relative epoch delay, got the since 0x${since.toString(16)}`),
        );
    });

    it.each([0, 35, 37, 56, 59])("refuses %i bytes", (length) => {
        expect(() => readCommitmentLockDelay(new Uint8Array(length))).toThrow(
            new TypeError(`commitment lock args must be 36, 57 or 58 bytes, got ${length}`),
        );
    });

    it("refuses what is not bytes", () => {
        expect(() => readCommitmentLockDelay(undefined as never)).toThrow(new TypeError("commitment lock args must be a Uint8Array"));
        expect(() => readCommitmentLockDelay(Array.from(new Uint8Array(57)) as never)).toThrow(
            new TypeError("commitment lock args must be a Uint8Array"),
        );
    });

    it("reads at the args' own offset when they are a view into a larger buffer", () => {
        const buffer = new Uint8Array(64);
        buffer.set(lockArgsOf(57, 0xa000000000000007n, 9n), 7);
        expect(readCommitmentLockDelay(buffer.subarray(7, 64))).toBe(7n);
    });
});

describe("readCommitmentLockVersion", () => {
    it.each(COMMITMENT_LOCK_LAYOUTS)("reads back the version the %s args were built with", (layout) => {
        expect(readCommitmentLockVersion(buildCommitmentLockArgs(XONLY, DELAY, 11, WITNESS, layout))).toBe(11);
        expect(readCommitmentLockVersion(buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, layout))).toBe(VERSION);
    });

    it.each([36, 57, 58])("reads the big-endian version out of %i bytes", (length) => {
        expect(readCommitmentLockVersion(lockArgsOf(length, 0xa000000000000000n, 0x0102n))).toBe(0x0102);
        expect(readCommitmentLockVersion(lockArgsOf(length, 0xa000000000000000n, 0n))).toBe(0);
    });

    it("reads up to the highest commitment number and refuses the next", () => {
        expect(readCommitmentLockVersion(lockArgsOf(36, 0n, 2n ** 48n - 1n))).toBe(2 ** 48 - 1);
        expect(() => readCommitmentLockVersion(lockArgsOf(36, 0n, 2n ** 48n))).toThrow(
            new RangeError("commitment lock args must carry a version of at most 281474976710655, got 281474976710656"),
        );
        expect(() => readCommitmentLockVersion(lockArgsOf(36, 0n, (1n << 64n) - 1n))).toThrow(RangeError);
    });

    it.each([0, 35, 37, 56, 59])("refuses %i bytes", (length) => {
        expect(() => readCommitmentLockVersion(new Uint8Array(length))).toThrow(
            new TypeError(`commitment lock args must be 36, 57 or 58 bytes, got ${length}`),
        );
    });

    it("refuses what is not bytes", () => {
        expect(() => readCommitmentLockVersion(null as never)).toThrow(new TypeError("commitment lock args must be a Uint8Array"));
        expect(() => readCommitmentLockVersion("ab".repeat(36) as never)).toThrow(
            new TypeError("commitment lock args must be a Uint8Array"),
        );
    });

    it("reads at the args' own offset when they are a view into a larger buffer", () => {
        const buffer = new Uint8Array(64);
        buffer.set(lockArgsOf(36, 0n, 9n), 5);
        expect(readCommitmentLockVersion(buffer.subarray(5, 41))).toBe(9);
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
        ["liquidCapacityShannons", { liquidCapacityShannons: 80_500_000_001n }],
        ["settlementLocalShannons", { settlementLocalShannons: 61_999_999_999n }],
        ["settlementRemoteShannons", { settlementRemoteShannons: 18_499_999_999n }],
        ["localReservedCkbShannons", { localReservedCkbShannons: 4_200_000_001n }],
        ["remoteReservedCkbShannons", { remoteReservedCkbShannons: 6_300_000_001n }],
        ["tlcs", { tlcs: [TLC] }],
        ["commitmentLock", { commitmentLock: { ...COMMITMENT_LOCK_TESTNET, hashType: "data" } }],
        ["udtTypeScript", { udtTypeScript: UDT_INPUT.udtTypeScript }],
        ["lockLayout", { lockLayout: "fullPaymentHash" }],
    ])("commits to %s", (_, overrides) => {
        expect(digestOf(overrides)).not.toBe(baseDigest);
    });

    it("digests the two layouts apart on otherwise equal inputs, with and without TLCs", () => {
        expect(digestOf({ lockLayout: "fullPaymentHash", tlcs: [] })).not.toBe(digestOf({ lockLayout: "legacy", tlcs: [] }));
        expect(digestOf({ lockLayout: "fullPaymentHash", tlcs: [TLC] })).not.toBe(digestOf({ lockLayout: "legacy", tlcs: [TLC] }));
    });

    it("binds a TLC's whole payment hash under fullPaymentHash and only its first 20 bytes under legacy", () => {
        expect(digestOf({ lockLayout: "legacy", tlcs: [TLC_TAIL] })).toBe(digestOf({ lockLayout: "legacy", tlcs: [TLC] }));
        expect(digestOf({ lockLayout: "fullPaymentHash", tlcs: [TLC_TAIL] })).not.toBe(
            digestOf({ lockLayout: "fullPaymentHash", tlcs: [TLC] }),
        );
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
        expect(() => digestOf({ liquidCapacityShannons: undefined })).toThrow(RangeError);
        expect(() => digestOf({ liquidCapacityShannons: -1n })).toThrow(RangeError);
        expect(() => digestOf({ liquidCapacityShannons: 1n << 128n })).toThrow(RangeError);
        expect(() => digestOf({ settlementLocalShannons: -1n })).toThrow(RangeError);
        expect(() => digestOf({ localReservedCkbShannons: 1n << 64n })).toThrow(RangeError);
        expect(() => digestOf({ fundingOutPoint: undefined })).toThrow(new TypeError("fundingOutPoint must be an object"));
        expect(() => digestOf({ fundingOutPoint: { txHash: new Uint8Array(31), index: 0 } })).toThrow(
            new TypeError("fundingOutPoint.txHash must be 32 bytes, got 31"),
        );
        expect(() => digestOf({ fundingOutPoint: { txHash: new Uint8Array(32), index: 2 ** 32 } })).toThrow(
            new RangeError("fundingOutPoint.index must be an integer between 0 and 4294967295, got 4294967296"),
        );
        expect(() => digestOf({ lockLayout: undefined })).toThrow(new TypeError("lockLayout must be one of legacy, fullPaymentHash"));
        expect(() => digestOf({ lockLayout: null as never })).toThrow(new TypeError("lockLayout must be one of legacy, fullPaymentHash"));
        expect(() => digestOf({ lockLayout: "full_payment_hash" as never })).toThrow(
            new TypeError("lockLayout must be one of legacy, fullPaymentHash"),
        );
    });
});
