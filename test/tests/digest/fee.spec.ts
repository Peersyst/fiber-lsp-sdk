import { hexToBytes } from "@noble/hashes/utils.js";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
import type { Script } from "../../../src/digest/digest.types";
import { calculateFee, commitmentTxSize, shutdownTxSize } from "../../../src/digest/fee";

const UDT_SCRIPT: Script = {
    codeHash: hexToBytes("aa".repeat(32)),
    hashType: "type",
    args: hexToBytes("bb".repeat(32)),
};

const CLOSE_SCRIPT_SHORT: Script = { codeHash: hexToBytes("cc".repeat(32)), hashType: "type", args: hexToBytes("dd".repeat(20)) };
const CLOSE_SCRIPT_LONG: Script = { codeHash: hexToBytes("ee".repeat(32)), hashType: "data1", args: hexToBytes("ff".repeat(32)) };

describe("commitmentTxSize", () => {
    // The 456-byte reference: a CKB channel with the shipped configs' two funding-lock cell deps.
    it("measures the canonical CKB mock at 456 bytes", () => {
        expect(commitmentTxSize(2, null, COMMITMENT_LOCK_TESTNET)).toBe(456);
    });

    it("measures the UDT mock with a 32-byte-args type script and three deps at 594 bytes", () => {
        expect(commitmentTxSize(3, UDT_SCRIPT, COMMITMENT_LOCK_TESTNET)).toBe(594);
    });

    it("grows by exactly one 37-byte dep per count", () => {
        expect(commitmentTxSize(3, null, COMMITMENT_LOCK_TESTNET) - commitmentTxSize(2, null, COMMITMENT_LOCK_TESTNET)).toBe(37);
    });

    it("refuses a cell dep count beyond the sanity bound", () => {
        expect(() => commitmentTxSize(256, null, COMMITMENT_LOCK_TESTNET)).toThrow(RangeError);
    });
});

describe("shutdownTxSize", () => {
    it("only depends on the scripts' sizes, not their order", () => {
        expect(shutdownTxSize(2, null, [CLOSE_SCRIPT_SHORT, CLOSE_SCRIPT_LONG])).toBe(
            shutdownTxSize(2, null, [CLOSE_SCRIPT_LONG, CLOSE_SCRIPT_SHORT]),
        );
    });

    it("grows with the args of either script", () => {
        expect(shutdownTxSize(2, null, [CLOSE_SCRIPT_LONG, CLOSE_SCRIPT_LONG])).toBe(
            shutdownTxSize(2, null, [CLOSE_SCRIPT_SHORT, CLOSE_SCRIPT_LONG]) + 12,
        );
    });

    it("adds the type script and the 16-byte data to both outputs on UDT channels", () => {
        const udtScriptLength = 53 + UDT_SCRIPT.args.length;
        expect(shutdownTxSize(2, UDT_SCRIPT, [CLOSE_SCRIPT_SHORT, CLOSE_SCRIPT_LONG])).toBe(
            shutdownTxSize(2, null, [CLOSE_SCRIPT_SHORT, CLOSE_SCRIPT_LONG]) + 2 * (udtScriptLength + 16),
        );
    });
});

describe("calculateFee", () => {
    it("truncates towards zero", () => {
        expect(calculateFee(1000n, 456)).toBe(456n);
        expect(calculateFee(1537n, 456)).toBe(700n);
        expect(calculateFee(1n, 456)).toBe(0n);
    });

    it("refuses a negative rate and a fee beyond u64", () => {
        expect(() => calculateFee(-1n, 456)).toThrow(RangeError);
        expect(() => calculateFee((1n << 64n) - 1n, 1001)).toThrow(RangeError);
    });
});
