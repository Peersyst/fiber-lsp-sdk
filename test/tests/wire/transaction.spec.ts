import { hexToBytes } from "@noble/hashes/utils.js";
import type { Transaction } from "../../../src/common";
import type { TransactionWire } from "../../../src/wire";
import { decodeTransaction, encodeTransaction } from "../../../src/wire";
import { refusal } from "../../utils/refusal";
import { ABOVE_U64, U64_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const TX_WIRE: TransactionWire = {
    version: "0x0",
    cell_deps: [
        { out_point: { tx_hash: `0x${"d1".repeat(32)}`, index: "0x0" }, dep_type: "dep_group" },
        { out_point: { tx_hash: `0x${"d2".repeat(32)}`, index: "0x2" }, dep_type: "code" },
    ],
    header_deps: [`0x${"e1".repeat(32)}`],
    inputs: [
        { since: "0x0", previous_output: { tx_hash: `0x${"a1".repeat(32)}`, index: "0x1" } },
        { since: U64_MAX_HEX, previous_output: { tx_hash: `0x${"a2".repeat(32)}`, index: "0xffffffff" } },
    ],
    outputs: [
        {
            capacity: "0x34e62ce00",
            lock: { code_hash: `0x${"b1".repeat(32)}`, hash_type: "data1", args: `0x${"c1".repeat(20)}` },
            type: { code_hash: `0x${"b2".repeat(32)}`, hash_type: "type", args: `0x${"c2".repeat(32)}` },
        },
        {
            capacity: U64_MAX_HEX,
            lock: { code_hash: `0x${"b3".repeat(32)}`, hash_type: "type", args: "0x" },
            type: null,
        },
    ],
    outputs_data: [`0x${"40420f00".padEnd(32, "0")}`, "0x"],
    witnesses: [`0x${"55".repeat(85)}`, "0x"],
};

const TX: Transaction = {
    version: 0,
    cellDeps: [
        { outPoint: { txHash: hexToBytes("d1".repeat(32)), index: 0 }, depType: "dep_group" },
        { outPoint: { txHash: hexToBytes("d2".repeat(32)), index: 2 }, depType: "code" },
    ],
    headerDeps: [hexToBytes("e1".repeat(32))],
    inputs: [
        { since: 0n, previousOutput: { txHash: hexToBytes("a1".repeat(32)), index: 1 } },
        { since: 2n ** 64n - 1n, previousOutput: { txHash: hexToBytes("a2".repeat(32)), index: 2 ** 32 - 1 } },
    ],
    outputs: [
        {
            capacityShannons: 14200000000n,
            lock: { codeHash: hexToBytes("b1".repeat(32)), hashType: "data1", args: hexToBytes("c1".repeat(20)) },
            type: { codeHash: hexToBytes("b2".repeat(32)), hashType: "type", args: hexToBytes("c2".repeat(32)) },
        },
        {
            capacityShannons: 2n ** 64n - 1n,
            lock: { codeHash: hexToBytes("b3".repeat(32)), hashType: "type", args: new Uint8Array(0) },
            type: null,
        },
    ],
    outputsData: [hexToBytes("40420f00".padEnd(32, "0")), new Uint8Array(0)],
    witnesses: [hexToBytes("55".repeat(85)), new Uint8Array(0)],
};

function decode(value: unknown): Transaction {
    return decodeTransaction({ value, path: "tx" });
}

describe("decodeTransaction", () => {
    it("reads CKB's JSON shape into the typed transaction", () => {
        expect(decode(TX_WIRE)).toEqual(TX);
    });

    it("reads a transaction with nothing in it", () => {
        const empty = { version: "0x0", cell_deps: [], header_deps: [], inputs: [], outputs: [], outputs_data: [], witnesses: [] };
        expect(decode(empty)).toEqual({
            version: 0,
            cellDeps: [],
            headerDeps: [],
            inputs: [],
            outputs: [],
            outputsData: [],
            witnesses: [],
        });
    });

    it("ignores members it does not know, the hash a TransactionView carries included", () => {
        expect(decode({ ...TX_WIRE, hash: `0x${"ff".repeat(32)}`, extra: 1 })).toEqual(TX);
    });

    it.each([
        ["version", "0"],
        ["version", "0x00"],
        ["version", "0x100000000"],
        ["version", 0],
        ["version", undefined],
        ["cell_deps", {}],
        ["cell_deps", undefined],
        ["cell_deps[0]", "dep"],
        ["cell_deps[0].dep_type", "DepGroup"],
        ["cell_deps[0].dep_type", "depgroup"],
        ["cell_deps[0].dep_type", 1],
        ["cell_deps[1].dep_type", undefined],
        ["cell_deps[0].out_point", undefined],
        ["cell_deps[1].out_point.tx_hash", `0x${"d2".repeat(31)}`],
        ["cell_deps[1].out_point.index", "0x02"],
        ["header_deps", undefined],
        ["header_deps", `0x${"e1".repeat(32)}`],
        ["header_deps[0]", `0x${"e1".repeat(31)}`],
        ["header_deps[0]", "e1".repeat(32)],
        ["inputs", null],
        ["inputs[0]", null],
        ["inputs[0].since", "0"],
        ["inputs[1].since", ABOVE_U64],
        ["inputs[1].since", undefined],
        ["inputs[0].previous_output", undefined],
        ["inputs[1].previous_output.index", "0x100000000"],
        ["outputs", undefined],
        ["outputs[0]", []],
        ["outputs[1].capacity", ABOVE_U64],
        ["outputs[0].capacity", "14200000000"],
        ["outputs[0].capacity", undefined],
        ["outputs[0].lock", null],
        ["outputs[1].lock.hash_type", "data3"],
        ["outputs[1].lock.args", ""],
        ["outputs[1].type", undefined],
        ["outputs[1].type", "null"],
        ["outputs[0].type.code_hash", `0x${"B2".repeat(32)}`],
        ["outputs_data", undefined],
        ["outputs_data[0]", "0x4"],
        ["outputs_data[1]", ""],
        ["witnesses", "0x"],
        ["witnesses[0]", "55".repeat(85)],
        ["witnesses[1]", null],
    ])("refuses %s = %p, naming the field", (path, value) => {
        expect(refusal(() => decode(withField(TX_WIRE, path, value))).path).toBe(`tx.${path}`);
    });

    it("names the deepest field that failed", () => {
        expect(refusal(() => decode(withField(TX_WIRE, "outputs[1].type", {}))).path).toBe("tx.outputs[1].type.code_hash");
        expect(refusal(() => decode(withField(TX_WIRE, "outputs[0].type.code_hash", "0x"))).path).toBe("tx.outputs[0].type.code_hash");
        expect(refusal(() => decode(withField(TX_WIRE, "cell_deps[1].out_point.index", 2))).path).toBe("tx.cell_deps[1].out_point.index");
    });

    it("refuses what is not an object", () => {
        expect(refusal(() => decode([TX_WIRE])).message).toBe("tx must be an object");
    });
});

describe("encodeTransaction", () => {
    it("writes CKB's JSON shape", () => {
        expect(encodeTransaction("tx", TX)).toEqual(TX_WIRE);
    });

    it("writes back exactly what it read, and reads back exactly what it wrote", () => {
        expect(encodeTransaction("tx", decode(TX_WIRE))).toEqual(TX_WIRE);
        expect(decode(encodeTransaction("tx", TX))).toEqual(TX);
    });

    it("writes the seven fields of a transaction and nothing else, in CKB's order", () => {
        expect(Object.keys(encodeTransaction("tx", decode({ ...TX_WIRE, hash: `0x${"ff".repeat(32)}` })))).toEqual([
            "version",
            "cell_deps",
            "header_deps",
            "inputs",
            "outputs",
            "outputs_data",
            "witnesses",
        ]);
    });

    it.each<[string, (tx: Transaction) => Transaction, Error]>([
        [
            "a version past a u32",
            (tx) => ({ ...tx, version: 2 ** 32 }),
            new RangeError("signedFundingTx.version must be an integer between 0 and 4294967295, got 4294967296"),
        ],
        [
            "a dep type outside CKB's two",
            (tx) => withField(tx, "cellDeps[1].depType", "depGroup"),
            new TypeError("signedFundingTx.cellDeps[1].depType must be one of code, dep_group"),
        ],
        [
            "a dep's tx hash of 31 bytes",
            (tx) => withField(tx, "cellDeps[0].outPoint.txHash", new Uint8Array(31)),
            new TypeError("signedFundingTx.cellDeps[0].outPoint.txHash must be 32 bytes, got 31"),
        ],
        [
            "a header dep of 31 bytes",
            (tx) => withField(tx, "headerDeps[0]", new Uint8Array(31)),
            new TypeError("signedFundingTx.headerDeps[0] must be 32 bytes, got 31"),
        ],
        [
            "an input's tx hash of 33 bytes",
            (tx) => withField(tx, "inputs[1].previousOutput.txHash", new Uint8Array(33)),
            new TypeError("signedFundingTx.inputs[1].previousOutput.txHash must be 32 bytes, got 33"),
        ],
        [
            "an output's lock with a short code hash",
            (tx) => withField(tx, "outputs[1].lock.codeHash", new Uint8Array(31)),
            new TypeError("signedFundingTx.outputs[1].lock.codeHash must be 32 bytes, got 31"),
        ],
        [
            "an output's type with a short code hash",
            (tx) => withField(tx, "outputs[0].type.codeHash", new Uint8Array(31)),
            new TypeError("signedFundingTx.outputs[0].type.codeHash must be 32 bytes, got 31"),
        ],
        [
            "an output's data as hex",
            (tx) => withField(tx, "outputsData[1]", "0x"),
            new TypeError("signedFundingTx.outputsData[1] must be a Uint8Array"),
        ],
        [
            "a witness as hex",
            (tx) => withField(tx, "witnesses[0]", `0x${"55".repeat(85)}`),
            new TypeError("signedFundingTx.witnesses[0] must be a Uint8Array"),
        ],
        [
            "an input's outpoint index past a u32",
            (tx) => withField(tx, "inputs[1].previousOutput.index", 2 ** 32),
            new RangeError("signedFundingTx.inputs[1].previousOutput.index must be an integer between 0 and 4294967295, got 4294967296"),
        ],
        [
            "a since past a u64",
            (tx) => withField(tx, "inputs[0].since", 2n ** 64n),
            new RangeError("signedFundingTx.inputs[0].since must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
        ],
        [
            "a capacity past a u64",
            (tx) => withField(tx, "outputs[0].capacityShannons", 2n ** 64n),
            new RangeError(
                "signedFundingTx.outputs[0].capacityShannons must be a bigint between 0 and 18446744073709551615, got 18446744073709551616",
            ),
        ],
        [
            "a negative capacity",
            (tx) => withField(tx, "outputs[0].capacityShannons", -1n),
            new RangeError("signedFundingTx.outputs[0].capacityShannons must be a bigint between 0 and 18446744073709551615, got -1"),
        ],
    ])("refuses %s, naming the field", (_, mutate, expected) => {
        expect(() => encodeTransaction("signedFundingTx", mutate(TX))).toThrow(expected);
    });
});
