import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { CellDep, CellOutput, Transaction } from "../../../src/common";
import { computeTxHash } from "../../../src/digest/tx-hash";
import { computeTxMessage } from "../../../src/digest/tx-message";
import { ckbHash } from "../../utils/ckb-hash";

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

const CELL_DEP: CellDep = { outPoint: { txHash: new Uint8Array(32).fill(0x11), index: 1 }, depType: "dep_group" };

const TX: Transaction = {
    version: 0,
    cellDeps: [CELL_DEP],
    headerDeps: [new Uint8Array(32).fill(0x22)],
    inputs: [{ since: 0x2000000000000001n, previousOutput: { txHash: new Uint8Array(32).fill(0x33), index: 2 } }],
    outputs: [PLAIN_OUTPUT, TYPED_OUTPUT],
    outputsData: [new Uint8Array(0), new Uint8Array(16).fill(0x99)],
    witnesses: [new Uint8Array(10).fill(0xaa)],
};

// The molecule RawTransaction of TX, written out by hand.
const RAW_TRANSACTION = hexToBytes(
    [
        // Table header: the total size, then the offset of each of the six fields.
        "d0010000" + "1c000000" + "20000000" + "49000000" + "6d000000" + "9d000000" + "ac010000",
        // version
        "00000000",
        // cell_deps: one item, the out point then the dep_group byte.
        "01000000" + "11".repeat(32) + "01000000" + "01",
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
    ].join(""),
);

// Computed apart from the SDK, with Python's blake2b under CKB's personalization over hand-written molecule bytes.
const TX_HASH = "9c4b79977a2942288b359319cf942b8aed2ebde808eead0893618ddfdbda8d9f";
const TX_MESSAGE = "0b251cc1b5b5780cb2a696996185e17a6802de97d0c8510ce3924c1d5e043a82";
const CODE_DEP_TX_HASH = "bfbba0ab2f827a506629d8a46fdc0a3b02628ea079ec06cf8109c99b22019ea8";
const TWO_DEPS_TX_HASH = "52364ef2e69dfe267b98b23900f1bfb44dd363fa91bc303d0dd868216f884bbe";
const SECOND_DEP: CellDep = { outPoint: { txHash: new Uint8Array(32).fill(0xab), index: 0 }, depType: "code" };

function hashOf(overrides: Partial<Transaction>): string {
    return bytesToHex(computeTxHash({ ...TX, ...overrides }));
}

describe("computeTxHash", () => {
    it("hashes the molecule raw transaction, cell deps included, under CKB's personalization", () => {
        expect(bytesToHex(ckbHash(RAW_TRANSACTION))).toBe(TX_HASH);
        expect(hashOf({})).toBe(TX_HASH);
    });

    it("writes each dep type as its molecule byte", () => {
        expect(hashOf({ cellDeps: [{ ...CELL_DEP, depType: "code" }] })).toBe(CODE_DEP_TX_HASH);
    });

    it("writes every cell dep, in order", () => {
        expect(hashOf({ cellDeps: [CELL_DEP, SECOND_DEP] })).toBe(TWO_DEPS_TX_HASH);
        expect(hashOf({ cellDeps: [SECOND_DEP, CELL_DEP] })).not.toBe(TWO_DEPS_TX_HASH);
    });

    it("is the message once the cell deps are emptied", () => {
        expect(hashOf({ cellDeps: [] })).toBe(TX_MESSAGE);
        expect(bytesToHex(computeTxMessage(TX))).toBe(TX_MESSAGE);
    });

    it("leaves the witnesses out", () => {
        expect(hashOf({ witnesses: [] })).toBe(TX_HASH);
        expect(hashOf({ witnesses: [new Uint8Array(112)] })).toBe(TX_HASH);
    });

    it.each<[string, CellDep]>([
        ["cellDeps[0].outPoint.txHash", { ...CELL_DEP, outPoint: { txHash: new Uint8Array(32).fill(0x12), index: 1 } }],
        ["cellDeps[0].outPoint.index", { ...CELL_DEP, outPoint: { txHash: new Uint8Array(32).fill(0x11), index: 2 } }],
    ])("commits to %s", (_, cellDep) => {
        expect(hashOf({ cellDeps: [cellDep] })).not.toBe(TX_HASH);
    });

    it.each<[string, Partial<Transaction>]>([
        ["version", { version: 1 }],
        ["headerDeps", { headerDeps: [] }],
        ["inputs", { inputs: [{ ...TX.inputs[0]!, since: 0n }] }],
        ["outputs", { outputs: [TYPED_OUTPUT, PLAIN_OUTPUT] }],
        ["outputsData", { outputsData: [new Uint8Array(0), new Uint8Array(16).fill(0x98)] }],
    ])("commits to %s, as the message does", (_, overrides) => {
        expect(hashOf(overrides)).not.toBe(TX_HASH);
    });

    it("takes an out point index up to a u32", () => {
        expect(() => hashOf({ cellDeps: [{ ...CELL_DEP, outPoint: { txHash: new Uint8Array(32), index: 2 ** 32 - 1 } }] })).not.toThrow();
    });

    it("refuses what is not a transaction", () => {
        expect(() => computeTxHash(undefined as never)).toThrow(new TypeError("transaction must be an object"));
        expect(() => computeTxHash([] as never)).toThrow(new TypeError("transaction must be an object"));
    });

    it("refuses cell deps that are not a list", () => {
        expect(() => hashOf({ cellDeps: undefined })).toThrow(new TypeError("transaction.cellDeps must be an array"));
        expect(() => hashOf({ cellDeps: CELL_DEP as never })).toThrow(new TypeError("transaction.cellDeps must be an array"));
    });

    it("refuses a malformed cell dep, one field at a time", () => {
        expect(() => hashOf({ cellDeps: [CELL_DEP, null as never] })).toThrow(new TypeError("transaction.cellDeps[1] must be an object"));
        expect(() => hashOf({ cellDeps: [{ ...CELL_DEP, outPoint: undefined as never }] })).toThrow(
            new TypeError("transaction.cellDeps[0].outPoint must be an object"),
        );
        expect(() => hashOf({ cellDeps: [{ ...CELL_DEP, outPoint: { txHash: new Uint8Array(31), index: 1 } }] })).toThrow(
            new TypeError("transaction.cellDeps[0].outPoint.txHash must be 32 bytes, got 31"),
        );
        expect(() => hashOf({ cellDeps: [{ ...CELL_DEP, outPoint: { txHash: new Uint8Array(32), index: 2 ** 32 } }] })).toThrow(
            new RangeError("transaction.cellDeps[0].outPoint.index must be an integer between 0 and 4294967295, got 4294967296"),
        );
        expect(() => hashOf({ cellDeps: [{ ...CELL_DEP, depType: undefined as never }] })).toThrow(
            new TypeError("transaction.cellDeps[0].depType must be one of code, dep_group"),
        );
        expect(() => hashOf({ cellDeps: [{ ...CELL_DEP, depType: "depGroup" as never }] })).toThrow(
            new TypeError("transaction.cellDeps[0].depType must be one of code, dep_group"),
        );
    });

    it("refuses the rest of a malformed transaction as the message does", () => {
        expect(() => hashOf({ version: 2 ** 32 })).toThrow(
            new RangeError("transaction.version must be an integer between 0 and 4294967295, got 4294967296"),
        );
        expect(() => hashOf({ headerDeps: undefined })).toThrow(new TypeError("transaction.headerDeps must be an array"));
        expect(() => hashOf({ outputs: [null as never] })).toThrow(new TypeError("transaction.outputs[0] must be an object"));
    });
});
