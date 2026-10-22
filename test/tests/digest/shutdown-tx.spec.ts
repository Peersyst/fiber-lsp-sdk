import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import type { CellOutput, Script, Transaction } from "../../../src/common";
import type { ClosingTxInput, ShutdownTxInput } from "../../../src/digest/digest.types";
import { buildClosingTx, computeClosingTxDigest, computeShutdownTxDigest, readClosingTx } from "../../../src/digest/shutdown-tx";
import { computeTxMessage } from "../../../src/digest/tx-message";
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

    // The funding pubkeys are not in the tx: a remote key on the other side of ours flips the outputs, one on ours changes nothing.
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

    it("refuses two sides that each fit in a u64 but together exceed the funding cell's", () => {
        const { toRemoteShannons, localReservedCkbShannons, remoteReservedCkbShannons } = BASE_INPUT;
        const fullCell = (1n << 64n) - 1n - toRemoteShannons - localReservedCkbShannons - remoteReservedCkbShannons;
        expect(() => digestOf({ toLocalShannons: fullCell })).not.toThrow();
        expect(() => digestOf({ toLocalShannons: fullCell + 1n })).toThrow(
            new RangeError("funding capacity must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
        );
    });

    it("refuses malformed inputs, one field at a time", () => {
        expect(() => digestOf({ remoteFundingPubkey: new Uint8Array(32) })).toThrow(TypeError);
        expect(() => digestOf({ localFeeRate: -1n })).toThrow(RangeError);
        expect(() => digestOf({ cellDepsCount: 256 })).toThrow(RangeError);
        expect(() => digestOf({ toLocalShannons: -1n })).toThrow(RangeError);
        expect(() => digestOf({ remoteReservedCkbShannons: 1n << 64n })).toThrow(RangeError);
        expect(() => digestOf({ localCloseScript: { ...LOCAL_CLOSE, codeHash: new Uint8Array(31) } })).toThrow(TypeError);
        expect(() => digestOf({ fundingOutPoint: { txHash: new Uint8Array(32), index: -1 } })).toThrow(
            new RangeError("fundingOutPoint.index must be an integer between 0 and 4294967295, got -1"),
        );
    });
});

// BASE_INPUT's close as its tx states it: each side's total less the fee its own rate pays (540 and 1157 shannons).
const CLOSING: ClosingTxInput = {
    fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf0), index: 0 },
    remoteFundingPubkey,
    localCloseScript: LOCAL_CLOSE,
    remoteCloseScript: REMOTE_CLOSE,
    localCapacityShannons: 66_199_999_460n,
    remoteCapacityShannons: 24_799_998_843n,
};

function closingDigestOf(overrides: Partial<ClosingTxInput>): string {
    return bytesToHex(computeClosingTxDigest(channelKeys, { ...CLOSING, ...overrides }));
}

describe("computeClosingTxDigest", () => {
    it("is the digest of the close the fee rates build, for the same outputs", () => {
        expect(computeClosingTxDigest(channelKeys, CLOSING)).toHaveLength(32);
        expect(closingDigestOf({})).toBe(baseDigest);
    });

    it.each<[keyof ClosingTxInput, Partial<ClosingTxInput>]>([
        ["fundingOutPoint", { fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf1), index: 0 } }],
        ["fundingOutPoint", { fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf0), index: 1 } }],
        ["localCloseScript", { localCloseScript: { ...LOCAL_CLOSE, args: hexToBytes("dd".repeat(21)) } }],
        ["remoteCloseScript", { remoteCloseScript: { ...REMOTE_CLOSE, hashType: "type" } }],
        ["localCapacityShannons", { localCapacityShannons: 66_199_999_461n }],
        ["remoteCapacityShannons", { remoteCapacityShannons: 24_799_998_842n }],
    ])("commits to %s", (_, overrides) => {
        expect(closingDigestOf(overrides)).not.toBe(baseDigest);
    });

    it("commits to which side owns which close script and which capacity", () => {
        expect(closingDigestOf({ localCloseScript: REMOTE_CLOSE, remoteCloseScript: LOCAL_CLOSE })).not.toBe(baseDigest);
        expect(
            closingDigestOf({
                localCapacityShannons: CLOSING.remoteCapacityShannons,
                remoteCapacityShannons: CLOSING.localCapacityShannons,
            }),
        ).not.toBe(baseDigest);
    });

    it("orders the outputs by the funding-pubkey sort alone", () => {
        const localPubkey = pubkeyOf(channelKeys.fundingKey);
        const localFirstInBase = compareBytes(localPubkey, remoteFundingPubkey) <= 0;
        const candidates = Array.from({ length: 256 }, (_, at) => pubkeyOf(ckbBlake2b(Uint8Array.of(at))));
        const sortsLikeBase = (candidate: Uint8Array): boolean => compareBytes(localPubkey, candidate) <= 0 === localFirstInBase;
        const sameSide = candidates.find(sortsLikeBase) as Uint8Array;
        const otherSide = candidates.find((candidate) => !sortsLikeBase(candidate)) as Uint8Array;
        expect(closingDigestOf({ remoteFundingPubkey: sameSide })).toBe(baseDigest);
        expect(closingDigestOf({ remoteFundingPubkey: otherSide })).not.toBe(baseDigest);
    });
});

const LOCAL_OUTPUT: CellOutput = { capacityShannons: 66_199_999_460n, lock: LOCAL_CLOSE, type: null };
const REMOTE_OUTPUT: CellOutput = { capacityShannons: 24_799_998_843n, lock: REMOTE_CLOSE, type: null };

function closingTx(outputs: CellOutput[]): Transaction {
    return {
        version: 0,
        cellDeps: [],
        headerDeps: [],
        inputs: [{ since: 0n, previousOutput: { txHash: new Uint8Array(32).fill(0xf0), index: 0 } }],
        outputs,
        outputsData: outputs.map(() => new Uint8Array(0)),
        witnesses: [],
    };
}

// One peer key on each side of the device's funding key, so both output orders are read.
const localFundingPubkey = pubkeyOf(channelKeys.fundingKey);
const peerKeys = Array.from({ length: 256 }, (_, at) => pubkeyOf(ckbBlake2b(Uint8Array.of(at))));
const SORTS_AFTER_LOCAL = peerKeys.find((key) => compareBytes(localFundingPubkey, key) < 0) as Uint8Array;
const SORTS_BEFORE_LOCAL = peerKeys.find((key) => compareBytes(localFundingPubkey, key) > 0) as Uint8Array;
const LOCAL_FIRST_TX = closingTx([LOCAL_OUTPUT, REMOTE_OUTPUT]);

describe("readClosingTx", () => {
    it.each<[string, Uint8Array, Transaction]>([
        ["first, its funding key sorting first", SORTS_AFTER_LOCAL, closingTx([LOCAL_OUTPUT, REMOTE_OUTPUT])],
        ["second, the peer's funding key sorting first", SORTS_BEFORE_LOCAL, closingTx([REMOTE_OUTPUT, LOCAL_OUTPUT])],
    ])("reads the device's output %s", (_, remoteFundingPubkey, tx) => {
        const closing = readClosingTx(channelKeys, remoteFundingPubkey, tx);
        expect(closing).toEqual({ ...CLOSING, remoteFundingPubkey });
        expect(bytesToHex(computeClosingTxDigest(channelKeys, closing))).toBe(bytesToHex(computeTxMessage(tx)));
    });

    // The order alone says which output is whose: the pinned close script is what catches a swap, not the digest.
    it("reads a tx in the other order with the sides swapped", () => {
        const closing = readClosingTx(channelKeys, SORTS_AFTER_LOCAL, closingTx([REMOTE_OUTPUT, LOCAL_OUTPUT]));
        expect(closing.localCloseScript).toEqual(REMOTE_CLOSE);
        expect(closing.localCapacityShannons).toBe(24_799_998_843n);
    });

    it("leaves the cell deps, header deps, data and witnesses to the digest comparison", () => {
        const tx: Transaction = {
            ...LOCAL_FIRST_TX,
            cellDeps: [{ outPoint: { txHash: new Uint8Array(32).fill(0x11), index: 0 }, depType: "code" }],
            headerDeps: [new Uint8Array(32).fill(0x22)],
            outputsData: [new Uint8Array(1), new Uint8Array(0)],
            witnesses: [new Uint8Array(112)],
        };
        expect(readClosingTx(channelKeys, SORTS_AFTER_LOCAL, tx)).toEqual({ ...CLOSING, remoteFundingPubkey: SORTS_AFTER_LOCAL });
    });

    it("takes capacities up to a u64 and refuses the next", () => {
        const max = (1n << 64n) - 1n;
        const atMax = closingTx([{ ...LOCAL_OUTPUT, capacityShannons: max }, REMOTE_OUTPUT]);
        expect(readClosingTx(channelKeys, SORTS_AFTER_LOCAL, atMax).localCapacityShannons).toBe(max);
        expect(() =>
            readClosingTx(channelKeys, SORTS_AFTER_LOCAL, closingTx([LOCAL_OUTPUT, { ...REMOTE_OUTPUT, capacityShannons: max + 1n }])),
        ).toThrow(new RangeError(`closing tx outputs[1].capacityShannons must be a bigint between 0 and ${max}, got ${max + 1n}`));
    });

    it.each<[string, unknown, Error]>([
        ["absent", undefined, new TypeError("remoteFundingPubkey must be a Uint8Array")],
        ["32 bytes", new Uint8Array(32), new TypeError("remoteFundingPubkey must be 33 bytes, got 32")],
    ])("refuses a peer funding key %s", (_, remoteFundingPubkey, error) => {
        expect(() => readClosingTx(channelKeys, remoteFundingPubkey as never, LOCAL_FIRST_TX)).toThrow(error);
    });

    it.each<[string, unknown, Error]>([
        ["absent", undefined, new TypeError("closing tx must be an object")],
        ["an array", [], new TypeError("closing tx must be an object")],
        ["without inputs", { ...LOCAL_FIRST_TX, inputs: undefined }, new TypeError("closing tx must have exactly 1 input, got none")],
        ["with no input", { ...LOCAL_FIRST_TX, inputs: [] }, new TypeError("closing tx must have exactly 1 input, got 0")],
        [
            "with two inputs",
            { ...LOCAL_FIRST_TX, inputs: [...LOCAL_FIRST_TX.inputs, ...LOCAL_FIRST_TX.inputs] },
            new TypeError("closing tx must have exactly 1 input, got 2"),
        ],
        ["whose input is not one", { ...LOCAL_FIRST_TX, inputs: [null] }, new TypeError("closing tx inputs[0] must be an object")],
        [
            "whose input spends nothing",
            { ...LOCAL_FIRST_TX, inputs: [{ since: 0n, previousOutput: undefined }] },
            new TypeError("closing tx inputs[0].previousOutput must be an object"),
        ],
        [
            "whose input spends a malformed out point",
            { ...LOCAL_FIRST_TX, inputs: [{ since: 0n, previousOutput: { txHash: new Uint8Array(31), index: 0 } }] },
            new TypeError("closing tx inputs[0].previousOutput.txHash must be 32 bytes, got 31"),
        ],
        ["without outputs", { ...LOCAL_FIRST_TX, outputs: undefined }, new TypeError("closing tx must have exactly 2 outputs, got none")],
        ["with one output", closingTx([LOCAL_OUTPUT]), new TypeError("closing tx must have exactly 2 outputs, got 1")],
        [
            "with three outputs",
            closingTx([LOCAL_OUTPUT, REMOTE_OUTPUT, REMOTE_OUTPUT]),
            new TypeError("closing tx must have exactly 2 outputs, got 3"),
        ],
        ["whose output is not one", closingTx([LOCAL_OUTPUT, null as never]), new TypeError("closing tx outputs[1] must be an object")],
        [
            "whose output has no capacity",
            closingTx([{ ...LOCAL_OUTPUT, capacityShannons: undefined as never }, REMOTE_OUTPUT]),
            new RangeError("closing tx outputs[0].capacityShannons must be a bigint between 0 and 18446744073709551615, got undefined"),
        ],
        [
            "whose output has no lock",
            closingTx([LOCAL_OUTPUT, { ...REMOTE_OUTPUT, lock: undefined as never }]),
            new TypeError("closing tx outputs[1].lock must be an object"),
        ],
        [
            "whose output's lock is malformed",
            closingTx([{ ...LOCAL_OUTPUT, lock: { ...LOCAL_CLOSE, hashType: "data3" as never } }, REMOTE_OUTPUT]),
            new TypeError("closing tx outputs[0].lock.hashType must be one of data, type, data1, data2"),
        ],
        [
            "whose first output carries a type script",
            closingTx([{ ...LOCAL_OUTPUT, type: REMOTE_CLOSE }, REMOTE_OUTPUT]),
            new TypeError("closing tx outputs[0] must carry no type script: a closing input is CKB only"),
        ],
        [
            "whose second output carries a type script",
            closingTx([LOCAL_OUTPUT, { ...REMOTE_OUTPUT, type: LOCAL_CLOSE }]),
            new TypeError("closing tx outputs[1] must carry no type script: a closing input is CKB only"),
        ],
        [
            "whose output leaves its type script out",
            closingTx([LOCAL_OUTPUT, { ...REMOTE_OUTPUT, type: undefined as never }]),
            new TypeError("closing tx outputs[1] must carry no type script: a closing input is CKB only"),
        ],
    ])("refuses a tx %s", (_, tx, error) => {
        expect(() => readClosingTx(channelKeys, SORTS_AFTER_LOCAL, tx as never)).toThrow(error);
    });
});

const ENTRY_POINTS: [string, (overrides: Partial<ClosingTxInput>) => unknown][] = [
    ["the digest", closingDigestOf],
    ["the builder", (overrides) => buildClosingTx(channelKeys, { ...CLOSING, ...overrides }, null)],
];

const UDT: Script = { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: new Uint8Array(0) };
const UDT_AMOUNTS = { typeScript: UDT, localAmountShannons: 62_000_000_000n, remoteAmountShannons: 18_500_000_000n };
const LOCAL_UDT_DATA = hexToBytes("00ec7c6f0e0000000000000000000000");
const REMOTE_UDT_DATA = hexToBytes("0099af4e040000000000000000000000");

describe("buildClosingTx", () => {
    it.each<[string, Uint8Array, Transaction]>([
        ["first, its funding key sorting first", SORTS_AFTER_LOCAL, closingTx([LOCAL_OUTPUT, REMOTE_OUTPUT])],
        ["second, the peer's funding key sorting first", SORTS_BEFORE_LOCAL, closingTx([REMOTE_OUTPUT, LOCAL_OUTPUT])],
    ])("spends the funding cell into the device's output %s, and reads back as its close", (_, remoteFundingPubkey, tx) => {
        const closing = { ...CLOSING, remoteFundingPubkey };
        const built = buildClosingTx(channelKeys, closing, null);
        expect(built).toEqual(tx);
        expect(readClosingTx(channelKeys, remoteFundingPubkey, built)).toEqual(closing);
    });

    it.each<[string, Uint8Array, CellOutput[], Uint8Array[]]>([
        ["first", SORTS_AFTER_LOCAL, [LOCAL_OUTPUT, REMOTE_OUTPUT], [LOCAL_UDT_DATA, REMOTE_UDT_DATA]],
        ["second", SORTS_BEFORE_LOCAL, [REMOTE_OUTPUT, LOCAL_OUTPUT], [REMOTE_UDT_DATA, LOCAL_UDT_DATA]],
    ])(
        "types both outputs by the UDT and keeps each side's amount beside its output, the device's %s",
        (_, remoteFundingPubkey, outputs, data) => {
            const built = buildClosingTx(channelKeys, { ...CLOSING, remoteFundingPubkey }, UDT_AMOUNTS);
            expect(built.outputs).toEqual(outputs.map((output) => ({ ...output, type: UDT })));
            expect(built.outputsData).toEqual(data);
        },
    );

    it.each(ENTRY_POINTS)("takes through %s capacities up to a u64 and refuses the next", (_, entry) => {
        const max = (1n << 64n) - 1n;
        expect(() => entry({ localCapacityShannons: max, remoteCapacityShannons: 0n })).not.toThrow();
        expect(() => entry({ localCapacityShannons: max + 1n })).toThrow(
            new RangeError(`localCapacityShannons must be a bigint between 0 and ${max}, got ${max + 1n}`),
        );
        expect(() => entry({ remoteCapacityShannons: max + 1n })).toThrow(
            new RangeError(`remoteCapacityShannons must be a bigint between 0 and ${max}, got ${max + 1n}`),
        );
    });

    it.each(ENTRY_POINTS)("refuses through %s malformed inputs, one field at a time", (_, entry) => {
        expect(() => entry({ fundingOutPoint: undefined })).toThrow(new TypeError("fundingOutPoint must be an object"));
        expect(() => entry({ fundingOutPoint: { txHash: new Uint8Array(31), index: 0 } })).toThrow(
            new TypeError("fundingOutPoint.txHash must be 32 bytes, got 31"),
        );
        expect(() => entry({ fundingOutPoint: { txHash: new Uint8Array(32), index: -1 } })).toThrow(
            new RangeError("fundingOutPoint.index must be an integer between 0 and 4294967295, got -1"),
        );
        expect(() => entry({ remoteFundingPubkey: undefined })).toThrow(new TypeError("remoteFundingPubkey must be a Uint8Array"));
        expect(() => entry({ remoteFundingPubkey: new Uint8Array(32) })).toThrow(
            new TypeError("remoteFundingPubkey must be 33 bytes, got 32"),
        );
        expect(() => entry({ localCloseScript: undefined })).toThrow(new TypeError("localCloseScript must be an object"));
        expect(() => entry({ localCloseScript: { ...LOCAL_CLOSE, codeHash: new Uint8Array(31) } })).toThrow(
            new TypeError("localCloseScript.codeHash must be 32 bytes, got 31"),
        );
        expect(() => entry({ remoteCloseScript: undefined })).toThrow(new TypeError("remoteCloseScript must be an object"));
        expect(() => entry({ remoteCloseScript: { ...REMOTE_CLOSE, args: "ff" as never } })).toThrow(
            new TypeError("remoteCloseScript.args must be a Uint8Array"),
        );
        expect(() => entry({ localCapacityShannons: undefined })).toThrow(RangeError);
        expect(() => entry({ localCapacityShannons: -1n })).toThrow(RangeError);
        expect(() => entry({ remoteCapacityShannons: undefined })).toThrow(RangeError);
        expect(() => entry({ remoteCapacityShannons: -1n })).toThrow(RangeError);
    });
});
