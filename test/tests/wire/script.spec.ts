import { hexToBytes } from "@noble/hashes/utils.js";
import type { OutPointWire, ScriptWire } from "../../../src/wire";
import { WireError, decodeOutPoint, decodeScript, decodeScriptOrNull } from "../../../src/wire";
import { refusal } from "../../utils/refusal";
import { withField } from "../../utils/with-field";

const SCRIPT: ScriptWire = { code_hash: `0x${"aa".repeat(32)}`, hash_type: "type", args: `0x${"bb".repeat(20)}` };
const OUT_POINT: OutPointWire = { tx_hash: `0x${"cc".repeat(32)}`, index: "0x0" };

describe("decodeScript", () => {
    it("reads CKB's JSON shape", () => {
        expect(decodeScript({ value: SCRIPT, path: "script" })).toEqual({
            codeHash: hexToBytes("aa".repeat(32)),
            hashType: "type",
            args: hexToBytes("bb".repeat(20)),
        });
    });

    it.each(["data", "type", "data1", "data2"] as const)("reads the %s hash type", (hashType) => {
        expect(decodeScript({ value: { ...SCRIPT, hash_type: hashType }, path: "script" }).hashType).toBe(hashType);
    });

    it("reads empty args", () => {
        expect(decodeScript({ value: { ...SCRIPT, args: "0x" }, path: "script" }).args).toEqual(new Uint8Array(0));
    });

    it.each([
        ["code_hash", `0x${"aa".repeat(31)}`],
        ["code_hash", `0x${"AA".repeat(32)}`],
        ["code_hash", "aa".repeat(32)],
        ["code_hash", undefined],
        ["hash_type", "data3"],
        ["hash_type", "Type"],
        ["hash_type", 1],
        ["hash_type", undefined],
        ["args", "0xb"],
        ["args", "bb"],
        ["args", null],
        ["args", undefined],
    ])("refuses %s = %p", (path, value) => {
        expect(refusal(() => decodeScript({ value: withField(SCRIPT, path, value), path: "script" })).path).toBe(`script.${path}`);
    });

    it.each([null, undefined, [], "0x"])("refuses %p as a script", (value) => {
        expect(refusal(() => decodeScript({ value, path: "script" })).message).toBe("script must be an object");
    });
});

describe("decodeScriptOrNull", () => {
    it("reads an explicit null as no script", () => {
        expect(decodeScriptOrNull({ value: null, path: "script" })).toBeNull();
    });

    it("reads a script", () => {
        expect(decodeScriptOrNull({ value: SCRIPT, path: "script" })?.hashType).toBe("type");
    });

    it.each([undefined, "null", {}, false])("refuses %p, since only null is no script", (value) => {
        expect(() => decodeScriptOrNull({ value, path: "script" })).toThrow(WireError);
    });
});

describe("decodeOutPoint", () => {
    it("reads CKB's JSON shape with a u32 index", () => {
        expect(decodeOutPoint({ value: OUT_POINT, path: "out_point" })).toEqual({ txHash: hexToBytes("cc".repeat(32)), index: 0 });
        expect(decodeOutPoint({ value: { ...OUT_POINT, index: "0xffffffff" }, path: "out_point" }).index).toBe(4294967295);
    });

    it.each([
        ["tx_hash", `0x${"cc".repeat(31)}`],
        ["tx_hash", undefined],
        ["index", "0x100000000"],
        ["index", "0x00"],
        ["index", "0"],
        ["index", 0],
        ["index", undefined],
    ])("refuses %s = %p", (path, value) => {
        expect(refusal(() => decodeOutPoint({ value: withField(OUT_POINT, path, value), path: "out_point" })).path).toBe(
            `out_point.${path}`,
        );
    });

    it("refuses what is not an object", () => {
        expect(refusal(() => decodeOutPoint({ value: null, path: "out_point" })).message).toBe("out_point must be an object");
    });
});
