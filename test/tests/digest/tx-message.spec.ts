import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { CellOutput, Transaction } from "../../../src/common";
import { computeRevocationContentMessage, computeTxMessage, serializeRawTransaction } from "../../../src/digest/tx-message";

const PLAIN_OUTPUT: CellOutput = {
    capacityShannons: 6_100_000_000n,
    lock: { codeHash: new Uint8Array(32).fill(0x44), hashType: "type", args: new Uint8Array(20).fill(0x55) },
    type: null,
};

const TYPED_OUTPUT: CellOutput = {
    capacityShannons: 14_200_000_000n,
    lock: { codeHash: new Uint8Array(32).fill(0x66), hashType: "data1", args: new Uint8Array(0) },
    type: { codeHash: new Uint8Array(32).fill(0x77), hashType: "data", args: new Uint8Array(32).fill(0x88) },
};

const TX: Transaction = {
    version: 0,
    cellDeps: [{ outPoint: { txHash: new Uint8Array(32).fill(0x11), index: 1 }, depType: "dep_group" }],
    headerDeps: [new Uint8Array(32).fill(0x22)],
    inputs: [{ since: 0x2000000000000001n, previousOutput: { txHash: new Uint8Array(32).fill(0x33), index: 2 } }],
    outputs: [PLAIN_OUTPUT, TYPED_OUTPUT],
    outputsData: [new Uint8Array(0), new Uint8Array(16).fill(0x99)],
    witnesses: [new Uint8Array(10).fill(0xaa)],
};

// Computed apart from the SDK, with Python's blake2b under CKB's personalization over hand-written molecule bytes.
const TX_MESSAGE = "0b251cc1b5b5780cb2a696996185e17a6802de97d0c8510ce3924c1d5e043a82";
const EMPTY_TX_MESSAGE = "f2e7a5362e217ed4d7f985af71b654cafadd0c3b6d6a6c13f1b13a6bfd0d3d14";

const ARGS = new Uint8Array(36).fill(0xab);
const EMPTY_DATA = hexToBytes("00000000");
const UDT_DATA = hexToBytes("10000000" + "99".repeat(16));
const REVOCATION_MESSAGE = "1cefdabc619a36ff8351308a9ea6da0be41c3cce8a76c1764536f68f1a9d041f";
const UDT_REVOCATION_MESSAGE = "9ad9657e4885afdc38cf8392915416a47221ab2ab4f8dbb6d07e37470b14cfd8";

function messageOf(overrides: Partial<Transaction>): string {
    return bytesToHex(computeTxMessage({ ...TX, ...overrides }));
}

describe("computeTxMessage", () => {
    it("hashes the molecule raw transaction under CKB's personalization", () => {
        expect(messageOf({})).toBe(TX_MESSAGE);
    });

    it("hashes the empty transaction", () => {
        const empty: Transaction = { version: 0, cellDeps: [], headerDeps: [], inputs: [], outputs: [], outputsData: [], witnesses: [] };
        expect(bytesToHex(computeTxMessage(empty))).toBe(EMPTY_TX_MESSAGE);
    });

    it("leaves the cell deps out, whatever they are", () => {
        expect(messageOf({ cellDeps: [] })).toBe(TX_MESSAGE);
        expect(messageOf({ cellDeps: [...TX.cellDeps, ...TX.cellDeps] })).toBe(TX_MESSAGE);
        // Not even read: a dep the CKB serializer would refuse never reaches it.
        expect(messageOf({ cellDeps: [null as never] })).toBe(TX_MESSAGE);
    });

    it("leaves the witnesses out", () => {
        expect(messageOf({ witnesses: [] })).toBe(TX_MESSAGE);
        expect(messageOf({ witnesses: [new Uint8Array(112)] })).toBe(TX_MESSAGE);
    });

    it.each<[string, Partial<Transaction>]>([
        ["version", { version: 1 }],
        ["headerDeps", { headerDeps: [] }],
        ["headerDeps", { headerDeps: [new Uint8Array(32).fill(0x23)] }],
        ["inputs[0].since", { inputs: [{ ...TX.inputs[0]!, since: 0n }] }],
        [
            "inputs[0].previousOutput",
            { inputs: [{ ...TX.inputs[0]!, previousOutput: { txHash: new Uint8Array(32).fill(0x33), index: 3 } }] },
        ],
        ["outputs order", { outputs: [TYPED_OUTPUT, PLAIN_OUTPUT] }],
        ["outputs[0].capacityShannons", { outputs: [{ ...PLAIN_OUTPUT, capacityShannons: 6_100_000_001n }, TYPED_OUTPUT] }],
        ["outputs[0].lock", { outputs: [{ ...PLAIN_OUTPUT, lock: { ...PLAIN_OUTPUT.lock, hashType: "data" } }, TYPED_OUTPUT] }],
        ["outputs[1].type", { outputs: [PLAIN_OUTPUT, { ...TYPED_OUTPUT, type: null }] }],
        ["outputsData", { outputsData: [new Uint8Array(0), new Uint8Array(16).fill(0x98)] }],
        ["outputsData", { outputsData: [new Uint8Array(0)] }],
    ])("commits to %s", (_, overrides) => {
        expect(messageOf(overrides)).not.toBe(TX_MESSAGE);
    });

    it("takes a version up to a u32, a since up to a u64, and a capacity up to a u64", () => {
        expect(() => messageOf({ version: 2 ** 32 - 1 })).not.toThrow();
        expect(() => messageOf({ inputs: [{ ...TX.inputs[0]!, since: (1n << 64n) - 1n }] })).not.toThrow();
        expect(() => messageOf({ outputs: [{ ...PLAIN_OUTPUT, capacityShannons: (1n << 64n) - 1n }] })).not.toThrow();
    });

    it("refuses what is not a transaction", () => {
        expect(() => computeTxMessage(undefined as never)).toThrow(new TypeError("transaction must be an object"));
        expect(() => computeTxMessage([] as never)).toThrow(new TypeError("transaction must be an object"));
    });

    it("refuses a malformed transaction, one field at a time", () => {
        expect(() => messageOf({ version: undefined })).toThrow(RangeError);
        expect(() => messageOf({ version: 2 ** 32 })).toThrow(
            new RangeError("transaction.version must be an integer between 0 and 4294967295, got 4294967296"),
        );
        expect(() => messageOf({ headerDeps: undefined })).toThrow(new TypeError("transaction.headerDeps must be an array"));
        expect(() => messageOf({ headerDeps: [new Uint8Array(31)] })).toThrow(
            new TypeError("transaction.headerDeps[0] must be 32 bytes, got 31"),
        );
        expect(() => messageOf({ inputs: undefined })).toThrow(new TypeError("transaction.inputs must be an array"));
        expect(() => messageOf({ outputs: undefined })).toThrow(new TypeError("transaction.outputs must be an array"));
        expect(() => messageOf({ outputsData: undefined })).toThrow(new TypeError("transaction.outputsData must be an array"));
    });

    it("refuses a malformed input, one field at a time", () => {
        const input = TX.inputs[0]!;
        expect(() => messageOf({ inputs: [null as never] })).toThrow(new TypeError("transaction.inputs[0] must be an object"));
        expect(() => messageOf({ inputs: [{ ...input, since: undefined as never }] })).toThrow(RangeError);
        expect(() => messageOf({ inputs: [{ ...input, since: 1n << 64n }] })).toThrow(
            new RangeError("transaction.inputs[0].since must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
        );
        expect(() => messageOf({ inputs: [{ ...input, previousOutput: undefined as never }] })).toThrow(
            new TypeError("transaction.inputs[0].previousOutput must be an object"),
        );
        expect(() => messageOf({ inputs: [{ ...input, previousOutput: { txHash: new Uint8Array(31), index: 0 } }] })).toThrow(
            new TypeError("transaction.inputs[0].previousOutput.txHash must be 32 bytes, got 31"),
        );
    });

    it("refuses a malformed output, one field at a time", () => {
        expect(() => messageOf({ outputs: [PLAIN_OUTPUT, null as never] })).toThrow(
            new TypeError("transaction.outputs[1] must be an object"),
        );
        expect(() => messageOf({ outputs: [{ ...PLAIN_OUTPUT, capacityShannons: undefined as never }] })).toThrow(RangeError);
        expect(() => messageOf({ outputs: [{ ...PLAIN_OUTPUT, capacityShannons: 1n << 64n }] })).toThrow(
            new RangeError(
                "transaction.outputs[0].capacityShannons must be a bigint between 0 and 18446744073709551615, got 18446744073709551616",
            ),
        );
        expect(() => messageOf({ outputs: [{ ...PLAIN_OUTPUT, lock: undefined as never }] })).toThrow(
            new TypeError("transaction.outputs[0].lock must be an object"),
        );
        expect(() => messageOf({ outputs: [{ ...PLAIN_OUTPUT, lock: { ...PLAIN_OUTPUT.lock, hashType: "data3" as never } }] })).toThrow(
            new TypeError("transaction.outputs[0].lock.hashType must be one of data, type, data1, data2"),
        );
        expect(() => messageOf({ outputs: [{ ...PLAIN_OUTPUT, type: undefined as never }] })).toThrow(
            new TypeError("transaction.outputs[0].type must be an object"),
        );
        expect(() => messageOf({ outputs: [{ ...TYPED_OUTPUT, type: { ...TYPED_OUTPUT.type!, args: undefined as never } }] })).toThrow(
            new TypeError("transaction.outputs[0].type.args must be a Uint8Array"),
        );
    });

    it("refuses output data that is not bytes", () => {
        expect(() => messageOf({ outputsData: [new Uint8Array(0), "99" as never] })).toThrow(
            new TypeError("transaction.outputsData[1] must be a Uint8Array"),
        );
        expect(() => messageOf({ outputsData: [undefined as never] })).toThrow(
            new TypeError("transaction.outputsData[0] must be a Uint8Array"),
        );
    });
});

// The molecule RawTransaction of TX, written out by hand: its fields after the cell deps, then the table without and with them.
const RAW_TAIL = [
    // header_deps
    "01000000" + "22".repeat(32),
    // inputs: the since, then the out point.
    "01000000" + "0100000000000020" + "33".repeat(32) + "02000000",
    // outputs: a dynvec of two CellOutput tables.
    "0f010000" + "0c000000" + "6d000000",
    "61000000" + "10000000" + "18000000" + "61000000" + "009d966b01000000",
    "49000000" + "10000000" + "30000000" + "31000000" + "44".repeat(32) + "01" + "14000000" + "55".repeat(20),
    "a2000000" + "10000000" + "18000000" + "4d000000" + "00ce624e03000000",
    "35000000" + "10000000" + "30000000" + "31000000" + "66".repeat(32) + "02" + "00000000",
    "55000000" + "10000000" + "30000000" + "31000000" + "77".repeat(32) + "00" + "20000000" + "88".repeat(32),
    // outputs_data: a dynvec of two Bytes.
    "24000000" + "0c000000" + "10000000" + "00000000" + "10000000" + "99".repeat(16),
].join("");
const RAW_WITHOUT_DEPS =
    "ab010000" + "1c000000" + "20000000" + "24000000" + "48000000" + "78000000" + "87010000" + "00000000" + "00000000" + RAW_TAIL;
const RAW_WITH_DEPS =
    "d0010000" +
    "1c000000" +
    "20000000" +
    "49000000" +
    "6d000000" +
    "9d000000" +
    "ac010000" +
    "00000000" +
    "01000000" +
    "11".repeat(32) +
    "01000000" +
    "01" +
    RAW_TAIL;

describe("serializeRawTransaction", () => {
    it("writes the cell deps when asked", () => {
        expect(bytesToHex(serializeRawTransaction(TX, true))).toBe(RAW_WITH_DEPS);
    });

    it("writes none without, not even reading them", () => {
        expect(bytesToHex(serializeRawTransaction(TX, false))).toBe(RAW_WITHOUT_DEPS);
        expect(bytesToHex(serializeRawTransaction({ ...TX, cellDeps: [null as never] }, false))).toBe(RAW_WITHOUT_DEPS);
        expect(bytesToHex(serializeRawTransaction({ ...TX, cellDeps: undefined as never }, false))).toBe(RAW_WITHOUT_DEPS);
    });

    it("reads the cell deps it writes", () => {
        expect(() => serializeRawTransaction({ ...TX, cellDeps: undefined as never }, true)).toThrow(
            new TypeError("transaction.cellDeps must be an array"),
        );
    });
});

describe("computeRevocationContentMessage", () => {
    it("hashes the output, its data and the args, in that order", () => {
        expect(bytesToHex(computeRevocationContentMessage(PLAIN_OUTPUT, EMPTY_DATA, ARGS))).toBe(REVOCATION_MESSAGE);
        expect(bytesToHex(computeRevocationContentMessage(TYPED_OUTPUT, UDT_DATA, ARGS))).toBe(UDT_REVOCATION_MESSAGE);
    });

    // Fiber hands over the data as the molecule slice, so the length header is part of what is hashed.
    it("hashes the data as given, length header and all", () => {
        const raw = bytesToHex(computeRevocationContentMessage(PLAIN_OUTPUT, new Uint8Array(0), ARGS));
        expect(raw).not.toBe(REVOCATION_MESSAGE);
    });

    it.each<[string, [CellOutput, Uint8Array, Uint8Array]]>([
        ["output", [{ ...PLAIN_OUTPUT, capacityShannons: 6_100_000_001n }, EMPTY_DATA, ARGS]],
        ["outputData", [PLAIN_OUTPUT, hexToBytes("01000000ff"), ARGS]],
        ["args", [PLAIN_OUTPUT, EMPTY_DATA, new Uint8Array(36).fill(0xac)]],
    ])("commits to %s", (_, [output, data, args]) => {
        expect(bytesToHex(computeRevocationContentMessage(output, data, args))).not.toBe(REVOCATION_MESSAGE);
    });

    it("refuses malformed content, one field at a time", () => {
        expect(() => computeRevocationContentMessage(undefined as never, EMPTY_DATA, ARGS)).toThrow(
            new TypeError("output must be an object"),
        );
        expect(() => computeRevocationContentMessage({ ...PLAIN_OUTPUT, capacityShannons: -1n }, EMPTY_DATA, ARGS)).toThrow(
            new RangeError("output.capacityShannons must be a bigint between 0 and 18446744073709551615, got -1"),
        );
        expect(() => computeRevocationContentMessage({ ...PLAIN_OUTPUT, lock: null as never }, EMPTY_DATA, ARGS)).toThrow(
            new TypeError("output.lock must be an object"),
        );
        expect(() => computeRevocationContentMessage({ ...PLAIN_OUTPUT, type: undefined as never }, EMPTY_DATA, ARGS)).toThrow(
            new TypeError("output.type must be an object"),
        );
        expect(() => computeRevocationContentMessage(PLAIN_OUTPUT, undefined as never, ARGS)).toThrow(
            new TypeError("outputData must be a Uint8Array"),
        );
        expect(() => computeRevocationContentMessage(PLAIN_OUTPUT, EMPTY_DATA, "ab" as never)).toThrow(
            new TypeError("args must be a Uint8Array"),
        );
    });
});
