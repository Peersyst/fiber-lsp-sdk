import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { AgentRequestError } from "../src/agent.error";
import { ckbTxHash, moleculeBytes, moleculeUint64, moleculeWitnessArgs, readCkbTxJson, readWitnessArgs } from "../src/ckb-tx";
import {
    TESTNET_CODE_DEPS_TX,
    TESTNET_CODE_DEPS_TX_HASH,
    TESTNET_GROUP_TX,
    TESTNET_GROUP_TX_HASH,
    TESTNET_TX,
    TESTNET_TX_HASH,
    TESTNET_TYPED_TX,
    TESTNET_TYPED_TX_HASH,
} from "./utils/ckb-testnet-tx";

type Json = Record<string, unknown>;

function tx(): Json {
    return structuredClone(TESTNET_TX) as unknown as Json;
}

function at(object: Json, path: readonly (string | number)[]): Json {
    let current: unknown = object;
    for (const key of path) current = (current as Record<string | number, unknown>)[key];
    return current as Json;
}

function withValue(path: readonly (string | number)[], key: string, value: unknown): Json {
    const copy = tx();
    at(copy, path)[key] = value;
    return copy;
}

function without(path: readonly (string | number)[], key: string): Json {
    const copy = tx();
    delete at(copy, path)[key];
    return copy;
}

function hex(bytes: Uint8Array): string {
    return `0x${bytesToHex(bytes)}`;
}

describe("ckbTxHash", () => {
    for (const [name, committed, hash] of [
        ["a public channel's funding", TESTNET_TX, TESTNET_TX_HASH],
        ["a split, its out points at nonzero indices", TESTNET_GROUP_TX, TESTNET_GROUP_TX_HASH],
        ["one with a since, a typed output and locks run as data, data1 and data2", TESTNET_TYPED_TX, TESTNET_TYPED_TX_HASH],
        ["one with a since and code deps", TESTNET_CODE_DEPS_TX, TESTNET_CODE_DEPS_TX_HASH],
    ] as const) {
        it(`hashes ${name} committed on testnet to the hash CKB gave it`, () => {
            assert.equal(hex(ckbTxHash(readCkbTxJson(committed, "tx"))), hash);
        });
    }

    it("refuses a hash type CKB does not have", () => {
        const [output] = TESTNET_TX.outputs;
        if (output === undefined) assert.fail("the vector has outputs");
        const unknown = { ...TESTNET_TX, outputs: [{ ...output, lock: { ...output.lock, hash_type: "data3" } }] };
        assert.throws(() => ckbTxHash(unknown), { message: "hash_type data3 is not one CKB has" });
    });

    it("leaves the witnesses out", () => {
        assert.equal(hex(ckbTxHash({ ...TESTNET_TX, witnesses: [] })), TESTNET_TX_HASH);
    });

    it("moves with each field it serializes, the witnesses aside", () => {
        const changed = [
            { ...TESTNET_TX, version: "0x1" },
            { ...TESTNET_TX, cell_deps: [] },
            { ...TESTNET_TX, header_deps: [TESTNET_TX_HASH] },
            { ...TESTNET_TX, inputs: TESTNET_TX.inputs.slice(0, 1) },
            { ...TESTNET_TX, outputs: TESTNET_TX.outputs.map((output, index) => (index === 0 ? { ...output, capacity: "0x1" } : output)) },
            { ...TESTNET_TX, outputs_data: ["0x00", "0x", "0x"] },
        ];
        for (const changedTx of changed) assert.notEqual(hex(ckbTxHash(changedTx)), TESTNET_TX_HASH);
    });
});

describe("readCkbTxJson", () => {
    it("reads a tx as sent", () => {
        assert.deepEqual(readCkbTxJson(TESTNET_TX, "tx"), TESTNET_TX);
    });

    it("reads an output with no type key as one with a null type", () => {
        assert.deepEqual(readCkbTxJson(without(["outputs", 0], "type"), "tx"), TESTNET_TX);
    });

    it("takes the largest version", () => {
        assert.equal(readCkbTxJson(withValue([], "version", "0xffffffff"), "tx").version, "0xffffffff");
    });

    it("takes the largest index and since", () => {
        const read = readCkbTxJson(withValue(["inputs", 0], "since", "0xffffffffffffffff"), "tx");
        assert.equal(read.inputs[0]?.since, "0xffffffffffffffff");
        const indexed = readCkbTxJson(withValue(["inputs", 0, "previous_output"], "index", "0xffffffff"), "tx");
        assert.equal(indexed.inputs[0]?.previous_output.index, "0xffffffff");
    });

    for (const value of [null, [], "tx"]) {
        it(`refuses a tx that is ${JSON.stringify(value)}`, () => {
            assert.throws(() => readCkbTxJson(value, "tx"), { message: "tx must be an object" });
        });
    }

    for (const [key, item] of [
        ["cell_deps", null],
        ["inputs", null],
        ["outputs", "x"],
    ] as const) {
        it(`refuses a ${key} item that is ${JSON.stringify(item)}`, () => {
            assert.throws(() => readCkbTxJson(withValue([], key, [item]), "tx"), { message: `tx.${key}[0] must be an object` });
        });
    }

    it("refuses an output whose type is not an object", () => {
        assert.throws(() => readCkbTxJson(withValue(["outputs", 0], "type", "0x"), "tx"), {
            message: "tx.outputs[0].type must be an object",
        });
    });

    it("refuses with the agent's request error, which a control route answers as a refusal", () => {
        assert.throws(() => readCkbTxJson(null, "tx"), AgentRequestError);
    });

    it("refuses a field the tx does not have", () => {
        assert.throws(() => readCkbTxJson({ ...TESTNET_TX, hash: TESTNET_TX_HASH }, "tx"), { message: "tx.hash is not a known field" });
    });

    for (const key of ["cell_deps", "header_deps", "inputs", "outputs", "outputs_data", "witnesses"]) {
        it(`refuses a tx without ${key}`, () => {
            assert.throws(() => readCkbTxJson(without([], key), "tx"), { message: `tx.${key} must be an array` });
        });
    }

    it("refuses a tx without version", () => {
        assert.throws(() => readCkbTxJson(without([], "version"), "tx"), { message: "tx.version must be a hex integer" });
    });

    for (const value of ["0", "0x", "0x00", "0x01", "0xA", "1", 0, " 0x0", "0x0 "]) {
        it(`refuses version ${JSON.stringify(value)}`, () => {
            assert.throws(() => readCkbTxJson(withValue([], "version", value), "tx"), { message: "tx.version must be a hex integer" });
        });
    }

    it("refuses a version past u32", () => {
        assert.throws(() => readCkbTxJson(withValue([], "version", "0x100000000"), "tx"), { message: "tx.version is out of range" });
    });

    it("refuses a cell dep with a field it does not have", () => {
        assert.throws(() => readCkbTxJson(withValue(["cell_deps", 0], "extra", 1), "tx"), {
            message: "tx.cell_deps[0].extra is not a known field",
        });
    });

    for (const value of [undefined, "Code", "data"]) {
        it(`refuses a cell dep whose dep_type is ${JSON.stringify(value)}`, () => {
            assert.throws(() => readCkbTxJson(withValue(["cell_deps", 0], "dep_type", value), "tx"), {
                message: "tx.cell_deps[0].dep_type must be code or dep_group",
            });
        });
    }

    it("refuses a cell dep without out_point", () => {
        assert.throws(() => readCkbTxJson(without(["cell_deps", 0], "out_point"), "tx"), {
            message: "tx.cell_deps[0].out_point must be an object",
        });
    });

    for (const value of [undefined, "0x00", `${TESTNET_TX_HASH}00`, TESTNET_TX_HASH.slice(2)]) {
        it(`refuses an out point whose tx_hash is ${JSON.stringify(value)}`, () => {
            assert.throws(() => readCkbTxJson(withValue(["cell_deps", 0, "out_point"], "tx_hash", value), "tx"), {
                message: "tx.cell_deps[0].out_point.tx_hash must be 32 bytes of 0x hex",
            });
        });
    }

    it("refuses an out point without index", () => {
        assert.throws(() => readCkbTxJson(without(["inputs", 1, "previous_output"], "index"), "tx"), {
            message: "tx.inputs[1].previous_output.index must be a hex integer",
        });
    });

    it("refuses an index past u32", () => {
        assert.throws(() => readCkbTxJson(withValue(["inputs", 0, "previous_output"], "index", "0x100000000"), "tx"), {
            message: "tx.inputs[0].previous_output.index is out of range",
        });
    });

    it("refuses an input without previous_output", () => {
        assert.throws(() => readCkbTxJson(without(["inputs", 0], "previous_output"), "tx"), {
            message: "tx.inputs[0].previous_output must be an object",
        });
    });

    it("refuses an input with a field it does not have", () => {
        assert.throws(() => readCkbTxJson(withValue(["inputs", 0], "extra", 1), "tx"), {
            message: "tx.inputs[0].extra is not a known field",
        });
    });

    it("refuses an out point with a field it does not have", () => {
        assert.throws(() => readCkbTxJson(withValue(["inputs", 0, "previous_output"], "extra", 1), "tx"), {
            message: "tx.inputs[0].previous_output.extra is not a known field",
        });
    });

    it("refuses an input without since", () => {
        assert.throws(() => readCkbTxJson(without(["inputs", 0], "since"), "tx"), { message: "tx.inputs[0].since must be a hex integer" });
    });

    it("refuses a since past u64", () => {
        assert.throws(() => readCkbTxJson(withValue(["inputs", 0], "since", "0x10000000000000000"), "tx"), {
            message: "tx.inputs[0].since is out of range",
        });
    });

    it("refuses an output without capacity", () => {
        assert.throws(() => readCkbTxJson(without(["outputs", 2], "capacity"), "tx"), {
            message: "tx.outputs[2].capacity must be a hex integer",
        });
    });

    it("refuses a capacity past u64", () => {
        assert.throws(() => readCkbTxJson(withValue(["outputs", 2], "capacity", "0x10000000000000000"), "tx"), {
            message: "tx.outputs[2].capacity is out of range",
        });
    });

    it("refuses an output without lock", () => {
        assert.throws(() => readCkbTxJson(without(["outputs", 1], "lock"), "tx"), { message: "tx.outputs[1].lock must be an object" });
    });

    it("refuses an output whose lock is not a script", () => {
        assert.throws(() => readCkbTxJson(withValue(["outputs", 1, "lock"], "hash_type", "data3"), "tx"), {
            message: "tx.outputs[1].lock.hash_type must be one of data, type, data1, data2",
        });
    });

    it("refuses an output whose type is not a script", () => {
        assert.throws(() => readCkbTxJson(withValue(["outputs", 0], "type", { code_hash: TESTNET_TX_HASH }), "tx"), {
            message: "tx.outputs[0].type.hash_type must be one of data, type, data1, data2",
        });
    });

    it("refuses an output with a field it does not have", () => {
        assert.throws(() => readCkbTxJson(withValue(["outputs", 0], "data", "0x"), "tx"), {
            message: "tx.outputs[0].data is not a known field",
        });
    });

    for (const key of ["header_deps", "outputs_data", "witnesses"] as const) {
        const message = key === "header_deps" ? `tx.${key}[0] must be 32 bytes of 0x hex` : `tx.${key}[0] must be 0x hex bytes`;
        for (const value of ["0x0", "ab", 1]) {
            it(`refuses a ${key} item ${JSON.stringify(value)}`, () => {
                const copy = tx();
                copy[key] = [value];
                if (key === "outputs_data") copy.outputs = TESTNET_TX.outputs.slice(0, 1);
                assert.throws(() => readCkbTxJson(copy, "tx"), { message });
            });
        }
    }

    for (const data of [
        ["0x", "0x"],
        ["0x", "0x", "0x", "0x"],
    ]) {
        it(`refuses ${data.length} outputs_data for 3 outputs`, () => {
            assert.throws(() => readCkbTxJson(withValue([], "outputs_data", data), "tx"), {
                message: `tx has 3 outputs but ${data.length} outputs_data`,
            });
        });
    }
});

describe("moleculeUint64", () => {
    it("writes eight little-endian bytes, up to u64's largest", () => {
        assert.equal(hex(moleculeUint64(0x0102n)), "0x0201000000000000");
        assert.equal(hex(moleculeUint64(0)), "0x0000000000000000");
        assert.equal(hex(moleculeUint64(0xffffffffffffffffn)), "0xffffffffffffffff");
    });
});

describe("WitnessArgs", () => {
    const signed = hexToBytes((TESTNET_TX.witnesses[0] ?? "").slice(2));

    it("reads a signed witness of testnet as a lock alone, and writes it back as it was", () => {
        const witness = readWitnessArgs(signed, "w");
        assert.equal(witness.lock?.length, 65);
        assert.deepEqual({ inputType: witness.inputType, outputType: witness.outputType }, { inputType: null, outputType: null });
        assert.equal(hex(moleculeWitnessArgs(witness)), TESTNET_TX.witnesses[0]);
    });

    it("writes one with no field set as the header alone", () => {
        assert.equal(hex(moleculeWitnessArgs({ lock: null, inputType: null, outputType: null })), "0x10000000100000001000000010000000");
    });

    it("reads the header alone as no field set", () => {
        assert.deepEqual(readWitnessArgs(hexToBytes("10000000100000001000000010000000"), "w"), {
            lock: null,
            inputType: null,
            outputType: null,
        });
    });

    it("reads all three fields", () => {
        const witness = { lock: new Uint8Array([1]), inputType: new Uint8Array([2, 3]), outputType: new Uint8Array() };
        assert.deepEqual(readWitnessArgs(moleculeWitnessArgs(witness), "w"), witness);
    });

    it("writes Bytes as its length then the bytes", () => {
        assert.equal(hex(moleculeBytes(new Uint8Array([0xab, 0xcd]))), "0x02000000abcd");
    });

    for (const [name, bytes] of [
        ["too short for its header", "0x1000000010000000100000001000"],
        ["sized other than its length", "0x11000000100000001000000010000000"],
        ["whose first offset is past its header", "0x10000000140000001000000010000000"],
        ["with a fourth field", "0x1400000014000000140000001400000014000000"],
        ["with an offset past its end", "0x10000000100000002000000010000000"],
        ["with offsets out of order", "0x1500000010000000150000001000000001000000ab"],
        ["with a field shorter than its Bytes", "0x1500000010000000150000001500000002000000ab"],
        ["with a field too short for a Bytes", "0x13000000100000001300000013000000000000"],
    ] as const) {
        it(`refuses one ${name}`, () => {
            assert.throws(() => readWitnessArgs(hexToBytes(bytes.slice(2)), "w"), { message: "w is not a WitnessArgs" });
        });
    }
});
