import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../src/common";
import { UINT64_MAX } from "../../../src/common";
import { moleculeCellOutput } from "../../../src/digest/utils/molecule.utils";
import { decodeMoleculeCellOutput } from "../../../src/wire";
import { refusal } from "../../utils/refusal";

const PATH = "content.output";

// 6_100_000_000 shannons, little-endian.
const CAPACITY = "009d966b01000000";
const CODE_HASH = "aa".repeat(32);
const ARGS = "14000000" + "bb".repeat(20);
const LOCK = "49000000" + "10000000" + "30000000" + "31000000" + CODE_HASH + "01" + ARGS;
const OUTPUT = "61000000" + "10000000" + "18000000" + "61000000" + CAPACITY + LOCK;

const TYPED_LOCK = "49000000" + "10000000" + "30000000" + "31000000" + CODE_HASH + "04" + ARGS;
const TYPE = "35000000" + "10000000" + "30000000" + "31000000" + "cc".repeat(32) + "02" + "00000000";
const TYPED_OUTPUT = "96000000" + "10000000" + "18000000" + "61000000" + "ffffffffffffffff" + TYPED_LOCK + TYPE;

function u32(value: number): string {
    return bytesToHex(new Uint8Array(new Uint32Array([value]).buffer));
}

function table(...fields: string[]): string {
    const headerLength = 4 * (fields.length + 1);
    const lengths = fields.map((part) => part.length / 2);
    const offsets = lengths.map((_, index) => headerLength + lengths.slice(0, index).reduce((sum, length) => sum + length, 0));
    const total = headerLength + lengths.reduce((sum, length) => sum + length, 0);
    return u32(total) + offsets.map(u32).join("") + fields.join("");
}

function decode(hex: string): ReturnType<typeof decodeMoleculeCellOutput> {
    return decodeMoleculeCellOutput({ value: `0x${hex}`, path: PATH });
}

function refused(hex: string): string {
    return refusal(() => decode(hex)).message;
}

describe("decodeMoleculeCellOutput", () => {
    it("reads a cell output without a type script", () => {
        expect(decode(OUTPUT)).toEqual({
            capacityShannons: 6_100_000_000n,
            lock: { codeHash: hexToBytes(CODE_HASH), hashType: "type", args: hexToBytes("bb".repeat(20)) },
            type: null,
        });
    });

    it("reads a cell output with a type script, its capacity at the u64 bound", () => {
        expect(decode(TYPED_OUTPUT)).toEqual({
            capacityShannons: UINT64_MAX,
            lock: { codeHash: hexToBytes(CODE_HASH), hashType: "data2", args: hexToBytes("bb".repeat(20)) },
            type: { codeHash: hexToBytes("cc".repeat(32)), hashType: "data1", args: new Uint8Array(0) },
        });
    });

    it("reads a zero capacity", () => {
        expect(decode(table("0000000000000000", LOCK, "")).capacityShannons).toBe(0n);
    });

    it.each([
        ["00", "data"],
        ["01", "type"],
        ["02", "data1"],
        ["04", "data2"],
    ] as const)("maps the hash type byte %s to %s", (byte, hashType) => {
        expect(decode(table(CAPACITY, table(CODE_HASH, byte, ARGS), "")).lock.hashType).toBe(hashType);
    });

    it("is the exact inverse of digest's writer", () => {
        for (const hex of [OUTPUT, TYPED_OUTPUT]) {
            const output = decode(hex);
            expect(bytesToHex(moleculeCellOutput(output.capacityShannons, output.lock, output.type))).toBe(hex);
        }
        const lock: Script = { codeHash: hexToBytes("11".repeat(32)), hashType: "data", args: new Uint8Array(0) };
        const type: Script = { codeHash: hexToBytes("22".repeat(32)), hashType: "type", args: hexToBytes("33".repeat(100)) };
        expect(decode(bytesToHex(moleculeCellOutput(1n, lock, type)))).toEqual({ capacityShannons: 1n, lock, type });
    });

    it("returns bytes of their own, not views over the whole output", () => {
        const { lock } = decode(OUTPUT);
        expect(lock.codeHash.buffer.byteLength).toBe(32);
        expect(lock.args.buffer.byteLength).toBe(20);
    });

    it.each([`0x${OUTPUT.toUpperCase()}`, OUTPUT, `0x${OUTPUT}0`, 1, null, undefined])("refuses %p as hex", (value) => {
        expect(refusal(() => decodeMoleculeCellOutput({ value, path: PATH })).message).toBe(
            `${PATH} must be whole bytes of 0x-prefixed lowercase hex`,
        );
    });

    describe("the table", () => {
        it.each([
            ["no bytes", ""],
            ["three bytes", "610000"],
            ["a size one short", "60000000" + OUTPUT.slice(8)],
            ["a size one long", "62000000" + OUTPUT.slice(8)],
            ["a trailing byte", OUTPUT + "00"],
            ["a missing last byte", OUTPUT.slice(0, -2)],
        ])("refuses %s", (_, hex) => {
            expect(refused(hex)).toBe(`${PATH} must be exactly as long as its size says`);
        });

        it.each([
            ["no fields, only its size", "04000000"],
            ["two fields", table(CAPACITY, LOCK)],
            ["four fields", table(CAPACITY, LOCK, "", "")],
        ])("refuses %s", (_, hex) => {
            expect(refused(hex)).toBe(`${PATH} must have exactly 3 fields`);
        });

        it.each([
            ["a header cut short", "0c000000" + "10000000" + "18000000"],
            ["a first offset one short", "61000000" + "0f000000" + "18000000" + "61000000" + CAPACITY + LOCK],
            ["a first offset one long", "61000000" + "11000000" + "18000000" + "61000000" + CAPACITY + LOCK],
        ])("refuses %s", (_, hex) => {
            expect(refused(hex)).toBe(`${PATH} must have a whole header`);
        });

        it.each([
            ["the lock before the capacity", "61000000" + "10000000" + "0f000000" + "61000000" + CAPACITY + LOCK],
            ["the type before the lock", "61000000" + "10000000" + "18000000" + "17000000" + CAPACITY + LOCK],
            ["the type one past the end", "61000000" + "10000000" + "18000000" + "62000000" + CAPACITY + LOCK],
            ["the lock past the end", "61000000" + "10000000" + "ffffffff" + "61000000" + CAPACITY + LOCK],
        ])("refuses %s", (_, hex) => {
            expect(refused(hex)).toBe(`${PATH} must have offsets in order`);
        });
    });

    describe("capacity", () => {
        it.each([
            ["seven bytes", table("009d966b010000", LOCK, "")],
            ["nine bytes", table("009d966b0100000000", LOCK, "")],
            ["no bytes", table("", LOCK, "")],
        ])("refuses %s", (_, hex) => {
            expect(refused(hex)).toBe(`${PATH}.capacity must be exactly 8 bytes`);
        });
    });

    describe.each(["lock", "type"] as const)("the %s script", (part) => {
        const embed = (script: string): string => (part === "lock" ? table(CAPACITY, script, "") : table(CAPACITY, LOCK, script));

        it("reads through the embedding the specs below break", () => {
            expect(decode(embed(LOCK))[part]).toEqual({
                codeHash: hexToBytes(CODE_HASH),
                hashType: "type",
                args: hexToBytes("bb".repeat(20)),
            });
        });

        it.each([
            ["three bytes", "490000"],
            ["a size one short", "48000000" + LOCK.slice(8)],
            ["a size one long", "4a000000" + LOCK.slice(8)],
            ["a trailing byte", LOCK + "00"],
        ])("refuses %s", (_, script) => {
            expect(refused(embed(script))).toBe(`${PATH}.${part} must be exactly as long as its size says`);
        });

        it("refuses an empty lock, where only the type may be absent", () => {
            expect(refused(table(CAPACITY, "", ""))).toBe(`${PATH}.lock must be exactly as long as its size says`);
        });

        it.each([
            ["no fields, only its size", "04000000"],
            ["two fields", table(CODE_HASH, "01")],
            ["four fields", table(CODE_HASH, "01", ARGS, "")],
        ])("refuses %s", (_, script) => {
            expect(refused(embed(script))).toBe(`${PATH}.${part} must have exactly 3 fields`);
        });

        it.each([
            ["the hash type before the code hash", "49000000" + "10000000" + "0f000000" + "31000000" + CODE_HASH + "01" + ARGS],
            ["the args before the hash type", "49000000" + "10000000" + "30000000" + "2f000000" + CODE_HASH + "01" + ARGS],
            ["the args past the end", "49000000" + "10000000" + "30000000" + "4a000000" + CODE_HASH + "01" + ARGS],
        ])("refuses %s", (_, script) => {
            expect(refused(embed(script))).toBe(`${PATH}.${part} must have offsets in order`);
        });

        it.each([
            ["31 bytes", "aa".repeat(31)],
            ["33 bytes", "aa".repeat(33)],
            ["no bytes", ""],
        ])("refuses a code hash of %s", (_, codeHash) => {
            expect(refused(embed(table(codeHash, "01", ARGS)))).toBe(`${PATH}.${part}.code_hash must be exactly 32 bytes`);
        });

        it.each([
            ["two bytes", "0100"],
            ["no bytes", ""],
        ])("refuses a hash type of %s", (_, hashType) => {
            expect(refused(embed(table(CODE_HASH, hashType, ARGS)))).toBe(`${PATH}.${part}.hash_type must be exactly 1 byte`);
        });

        it.each(["03", "05", "06", "08", "ff"])("refuses the hash type byte %s, which CKB does not define", (hashType) => {
            expect(refused(embed(table(CODE_HASH, hashType, ARGS)))).toBe(
                `${PATH}.${part}.hash_type must be one of data, type, data1, data2`,
            );
        });

        it.each([
            ["a length one short", "13000000" + "bb".repeat(20)],
            ["a length one long", "15000000" + "bb".repeat(20)],
            ["a trailing byte", ARGS + "00"],
            ["no length", ""],
            ["three bytes of length", "000000"],
        ])("refuses args with %s", (_, args) => {
            expect(refused(embed(table(CODE_HASH, "01", args)))).toBe(`${PATH}.${part}.args must be exactly as long as its length says`);
        });

        it("reads empty args", () => {
            expect(decode(embed(table(CODE_HASH, "01", "00000000")))[part]?.args).toEqual(new Uint8Array(0));
        });
    });
});
