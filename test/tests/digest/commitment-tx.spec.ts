import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import {
    buildCommitmentLockArgs,
    buildCommitmentSettlementWitness,
    buildCommitmentTx,
    buildCommitmentTxAndSettlement,
    computeCommitmentTxDigest,
    readCommitmentLockDelay,
    readCommitmentLockLayout,
    readCommitmentLockSettled,
    readCommitmentLockSettlementHash,
    readCommitmentLockVersion,
} from "../../../src/digest/commitment-tx";
import { blake160 } from "../../../src/common/utils/ckb-hash.utils";
import { COMMITMENT_LOCK_LAYOUTS, COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
import type { CommitmentTxInput, SettlementTlc } from "../../../src/digest/digest.types";
import { readSettlementBody } from "../../../src/digest/settlement-unlock";
import { aggregateXOnlyPubkey } from "../../../src/digest/utils/digest.utils";
import { ckbHash } from "../../utils/ckb-hash";
import { toCommitmentTxInput } from "../../utils/digest-inputs";
import { loadInteropVectors } from "../../utils/interop-vectors";

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

// Key hash, delay since, version, settlement hash, then the settlement flag; the feature byte follows under fullPaymentHash.
const SETTLEMENT_ARGS = "a0".repeat(20) + "b0".repeat(8) + "c0".repeat(8) + "d0".repeat(20);

describe("readCommitmentLockSettlementHash", () => {
    it.each(COMMITMENT_LOCK_LAYOUTS)("reads back the witness hash the %s args were built with", (layout) => {
        const args = buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, layout);
        expect(readCommitmentLockSettlementHash(args)).toEqual(blake160(WITNESS));
    });

    it.each(["00", "01", "0001", "0101"])("reads bytes 36 to 56 of the args ending in %s", (tail) => {
        expect(bytesToHex(readCommitmentLockSettlementHash(hexToBytes(SETTLEMENT_ARGS + tail)))).toBe("d0".repeat(20));
    });

    it("returns its own bytes, which a later change to the args never reaches", () => {
        const args = hexToBytes(SETTLEMENT_ARGS + "00");
        const hash = readCommitmentLockSettlementHash(args);
        args.fill(0x77);
        expect(bytesToHex(hash)).toBe("d0".repeat(20));
    });

    it("reads at the args' own offset when they are a view into a larger buffer", () => {
        const buffer = new Uint8Array(64);
        buffer.set(hexToBytes(SETTLEMENT_ARGS + "01"), 5);
        expect(bytesToHex(readCommitmentLockSettlementHash(buffer.subarray(5, 62)))).toBe("d0".repeat(20));
    });

    it.each([0, 36, 56, 59])("refuses %i bytes, a revocation's 36 included", (length) => {
        expect(() => readCommitmentLockSettlementHash(new Uint8Array(length))).toThrow(
            new TypeError(`commitment lock args must be 57 or 58 bytes, got ${length}`),
        );
    });

    it("refuses 58 bytes without the feature byte, and what is not bytes", () => {
        expect(() => readCommitmentLockSettlementHash(hexToBytes(SETTLEMENT_ARGS + "0000"))).toThrow(
            new TypeError("commitment lock args of 58 bytes must end in the feature byte 0x01, got 0x00"),
        );
        expect(() => readCommitmentLockSettlementHash(SETTLEMENT_ARGS as never)).toThrow(
            new TypeError("commitment lock args must be a Uint8Array"),
        );
    });
});

describe("readCommitmentLockSettled", () => {
    it.each(COMMITMENT_LOCK_LAYOUTS)("reads the %s args of a commitment as not settled", (layout) => {
        expect(readCommitmentLockSettled(buildCommitmentLockArgs(XONLY, DELAY, VERSION, WITNESS, layout))).toBe(false);
    });

    it.each([
        ["00", false],
        ["01", true],
        ["0001", false],
        ["0101", true],
    ])("reads the args ending in %s as settled: %p", (tail, settled) => {
        expect(readCommitmentLockSettled(hexToBytes(SETTLEMENT_ARGS + tail))).toBe(settled);
    });

    it("reads at the args' own offset when they are a view into a larger buffer", () => {
        const buffer = new Uint8Array(64);
        buffer.set(hexToBytes(SETTLEMENT_ARGS + "01"), 3);
        expect(readCommitmentLockSettled(buffer.subarray(3, 60))).toBe(true);
    });

    it.each(["02", "ff", "0201"])("refuses the args ending in %s, a flag fiber never writes", (tail) => {
        expect(() => readCommitmentLockSettled(hexToBytes(SETTLEMENT_ARGS + tail))).toThrow(
            new TypeError(`commitment lock args must carry the settlement flag 0x00 or 0x01, got 0x${tail.slice(0, 2)}`),
        );
    });

    it.each([0, 36, 56, 59])("refuses %i bytes, a revocation's 36 included", (length) => {
        expect(() => readCommitmentLockSettled(new Uint8Array(length))).toThrow(
            new TypeError(`commitment lock args must be 57 or 58 bytes, got ${length}`),
        );
    });

    it("refuses 58 bytes without the feature byte, and what is not bytes", () => {
        expect(() => readCommitmentLockSettled(hexToBytes(SETTLEMENT_ARGS + "0100"))).toThrow(
            new TypeError("commitment lock args of 58 bytes must end in the feature byte 0x01, got 0x00"),
        );
        expect(() => readCommitmentLockSettled(undefined as never)).toThrow(new TypeError("commitment lock args must be a Uint8Array"));
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
});

const localFundingPubkey = pubkeyOf(channelKeys.fundingKey);

const ENTRY_POINTS: [string, (overrides: Partial<CommitmentTxInput>) => unknown][] = [
    ["the digest", digestOf],
    ["the builder", (overrides) => buildCommitmentTx(channelKeys, { ...BASE_INPUT, ...overrides })],
];

describe("buildCommitmentTx", () => {
    // The liquid amount and both reserves, less the 456-shannon fee.
    it("spends the funding cell into the one commitment cell, with no deps or witnesses", () => {
        expect(buildCommitmentTx(channelKeys, BASE_INPUT)).toEqual({
            version: 0,
            cellDeps: [],
            headerDeps: [],
            inputs: [{ since: 0n, previousOutput: { txHash: new Uint8Array(32).fill(0xf0), index: 0 } }],
            outputs: [
                { capacityShannons: 90_999_999_544n, lock: { ...COMMITMENT_LOCK_TESTNET, args: expect.any(Uint8Array) }, type: null },
            ],
            outputsData: [new Uint8Array(0)],
            witnesses: [],
        });
    });

    it.each<[string, Partial<CommitmentTxInput>, [Uint8Array, Uint8Array], number]>([
        ["the peer's commitment, legacy", { forRemote: true, lockLayout: "legacy" }, [localFundingPubkey, remoteFundingPubkey], 57],
        [
            "the device's commitment, fullPaymentHash",
            { forRemote: false, lockLayout: "fullPaymentHash" },
            [remoteFundingPubkey, localFundingPubkey],
            58,
        ],
    ])("locks %s under the role-ordered key, the delay, the version and the layout", (_, overrides, orderedPubkeys, length) => {
        const args = buildCommitmentTx(channelKeys, { ...BASE_INPUT, ...overrides }).outputs[0]?.lock.args ?? new Uint8Array(0);
        expect(args).toHaveLength(length);
        expect(bytesToHex(args.subarray(0, 20))).toBe(bytesToHex(blake160(aggregateXOnlyPubkey(orderedPubkeys))));
        expect(readCommitmentLockDelay(args)).toBe((1n << 40n) | 1n);
        expect(readCommitmentLockVersion(args)).toBe(11);
        expect(readCommitmentLockLayout(args)).toBe(overrides.lockLayout);
    });

    // Only the reserves, less the 594-shannon fee; the liquid amount is the u128 data.
    it("carries the UDT as the cell's type and the liquid amount as its data", () => {
        const tx = buildCommitmentTx(channelKeys, UDT_INPUT);
        expect(tx.outputs).toEqual([
            {
                capacityShannons: 10_499_999_406n,
                lock: { ...COMMITMENT_LOCK_TESTNET, args: expect.any(Uint8Array) },
                type: { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: hexToBytes("bb".repeat(32)) },
            },
        ]);
        expect(tx.outputsData).toEqual([hexToBytes("000080186bf13a5e2b00000000000000")]);
    });

    it.each(ENTRY_POINTS)("refuses through %s a fee the capacity cannot cover", (_, entry) => {
        expect(() => entry({ commitmentFeeRate: (1n << 63n) / 456n })).toThrow(RangeError);
    });

    it.each(ENTRY_POINTS)("refuses through %s malformed inputs, one field at a time", (_, entry) => {
        expect(() => entry({ remoteFundingPubkey: new Uint8Array(32) })).toThrow(TypeError);
        expect(() => entry({ remoteTlcBasePubkey: new Uint8Array(34) })).toThrow(TypeError);
        expect(() => entry({ commitmentNumber: 2 ** 48 })).toThrow(RangeError);
        expect(() => entry({ commitmentDelayEpoch: 1n << 56n })).toThrow(RangeError);
        expect(() => entry({ commitmentFeeRate: -1n })).toThrow(RangeError);
        expect(() => entry({ cellDepsCount: 256 })).toThrow(RangeError);
        expect(() => entry({ liquidCapacityShannons: undefined })).toThrow(RangeError);
        expect(() => entry({ liquidCapacityShannons: -1n })).toThrow(RangeError);
        expect(() => entry({ liquidCapacityShannons: 1n << 128n })).toThrow(RangeError);
        expect(() => entry({ settlementLocalShannons: -1n })).toThrow(RangeError);
        expect(() => entry({ localReservedCkbShannons: 1n << 64n })).toThrow(RangeError);
        expect(() => entry({ settlementRemoteShannons: undefined })).toThrow(
            new RangeError(
                "settlementRemoteShannons must be a bigint between 0 and 340282366920938463463374607431768211455, got undefined",
            ),
        );
        expect(() => entry({ settlementRemoteShannons: -1n })).toThrow(
            new RangeError("settlementRemoteShannons must be a bigint between 0 and 340282366920938463463374607431768211455, got -1"),
        );
        expect(() => entry({ settlementRemoteShannons: 1n << 128n })).toThrow(
            new RangeError(
                "settlementRemoteShannons must be a bigint between 0 and 340282366920938463463374607431768211455, got 340282366920938463463374607431768211456",
            ),
        );
        expect(() => entry({ remoteReservedCkbShannons: undefined })).toThrow(
            new RangeError("remoteReservedCkbShannons must be a bigint between 0 and 18446744073709551615, got undefined"),
        );
        expect(() => entry({ remoteReservedCkbShannons: -1n })).toThrow(
            new RangeError("remoteReservedCkbShannons must be a bigint between 0 and 18446744073709551615, got -1"),
        );
        expect(() => entry({ remoteReservedCkbShannons: 1n << 64n })).toThrow(
            new RangeError("remoteReservedCkbShannons must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
        );
        expect(() => entry({ fundingOutPoint: undefined })).toThrow(new TypeError("fundingOutPoint must be an object"));
        expect(() => entry({ fundingOutPoint: { txHash: new Uint8Array(31), index: 0 } })).toThrow(
            new TypeError("fundingOutPoint.txHash must be 32 bytes, got 31"),
        );
        expect(() => entry({ fundingOutPoint: { txHash: new Uint8Array(32), index: 2 ** 32 } })).toThrow(
            new RangeError("fundingOutPoint.index must be an integer between 0 and 4294967295, got 4294967296"),
        );
        expect(() => entry({ lockLayout: undefined })).toThrow(new TypeError("lockLayout must be one of legacy, fullPaymentHash"));
        expect(() => entry({ lockLayout: null as never })).toThrow(new TypeError("lockLayout must be one of legacy, fullPaymentHash"));
        expect(() => entry({ lockLayout: "full_payment_hash" as never })).toThrow(
            new TypeError("lockLayout must be one of legacy, fullPaymentHash"),
        );
    });
});

describe("buildCommitmentTxAndSettlement", () => {
    it("builds the tx and the body the commitment builders build apart, the body the one its lock args commit", () => {
        const { transaction, settlementWitness } = buildCommitmentTxAndSettlement(channelKeys, BASE_INPUT);
        expect(transaction).toEqual(buildCommitmentTx(channelKeys, BASE_INPUT));
        expect(settlementWitness).toEqual(buildCommitmentSettlementWitness(channelKeys, BASE_INPUT));
        expect(readCommitmentLockSettlementHash(transaction.outputs[0]?.lock.args ?? new Uint8Array(0))).toEqual(
            blake160(settlementWitness),
        );
    });
});

describe("buildCommitmentSettlementWitness", () => {
    const DEVICE_KEY_HASH = ckbHash(pubkeyOf(channelKeys.tlcBaseKey)).slice(0, 20);
    const PEER_KEY_HASH = ckbHash(remoteTlcBasePubkey).slice(0, 20);

    function bodyOf(input: CommitmentTxInput) {
        return readSettlementBody(buildCommitmentSettlementWitness(channelKeys, input), input.lockLayout);
    }

    // The peer's commitment puts the peer's balance first; the device's own puts the device's.
    it.each<[string, boolean, [Uint8Array, bigint][]]>([
        [
            "the peer's",
            true,
            [
                [PEER_KEY_HASH, 24_800_000_000n],
                [DEVICE_KEY_HASH, 66_200_000_000n],
            ],
        ],
        [
            "the device's",
            false,
            [
                [DEVICE_KEY_HASH, 66_200_000_000n],
                [PEER_KEY_HASH, 24_800_000_000n],
            ],
        ],
    ])("settles each side's balance with its reserve on %s CKB commitment", (_, forRemote, balances) => {
        const body = bodyOf({ ...BASE_INPUT, forRemote });
        expect(body.tlcEntries).toEqual([]);
        expect(body.balances).toEqual(balances.map(([pubkeyHash, amountShannons]) => ({ pubkeyHash, amountShannons })));
    });

    it("leaves the reserves, capacity only, out of a UDT commitment's balances", () => {
        expect(bodyOf(UDT_INPUT).balances).toEqual([
            { pubkeyHash: PEER_KEY_HASH, amountShannons: 300_000_000_000_000_000_000n },
            { pubkeyHash: DEVICE_KEY_HASH, amountShannons: 500_000_000_000_000_000_000n },
        ]);
    });

    it("carries the commitment's TLCs", () => {
        expect(bodyOf({ ...BASE_INPUT, tlcs: [TLC] }).tlcEntries).toHaveLength(1);
    });

    it.each(COMMITMENT_LOCK_LAYOUTS)("is the body the %s commitment's lock args commit", (lockLayout) => {
        const input: CommitmentTxInput = { ...BASE_INPUT, tlcs: [TLC], lockLayout };
        const args = buildCommitmentTx(channelKeys, input).outputs[0]?.lock.args ?? new Uint8Array(0);
        expect(readCommitmentLockSettlementHash(args)).toEqual(blake160(buildCommitmentSettlementWitness(channelKeys, input)));
    });

    describe("fiber's commitments", () => {
        const vectors = loadInteropVectors();
        const keys = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));

        it.each(vectors.digest.commitment_cases.map((kase) => [kase.name, kase] as const))("rebuilds the witness of %s", (_, kase) => {
            const witness = buildCommitmentSettlementWitness(keys, toCommitmentTxInput(kase, vectors.digest.remote));
            expect(bytesToHex(witness)).toBe(kase.settlement_witness);
        });
    });
});
