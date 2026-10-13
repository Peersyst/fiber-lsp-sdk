import type { Script } from "../../../src/common";
import type { ChannelPins } from "../../../src/policy";
import { assertChannelOpening, openingChannelPins } from "../../../src/policy";
import { toScript, toShutdownTxInput } from "../../utils/digest-inputs";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";

const digest = loadInteropVectors().digest;

const LOCAL_CLOSE_SCRIPT_PIN =
    "4900000010000000300000003100000074d3f63a22681bdb6ff6512866db95264338cfaee12f71e28b9f23c414990c9c0114000000da694932ba803b4c07f6e3a9b6b2ea3f9c6c66c7";

// Args under 57 bytes: a 99 CKB reserve.
const CLOSE_SCRIPT: Script = { codeHash: new Uint8Array(32), hashType: "type", args: new Uint8Array(20) };

describe("assertChannelOpening", () => {
    it.each([
        ["exactly the reserve", "9900000000"],
        ["one shannon below u64's maximum", "18446744073709551614"],
    ])("accepts a funded amount of %s", (_, funded) => {
        expect(() => assertChannelOpening(funded, CLOSE_SCRIPT)).not.toThrow();
    });

    it.each([
        [
            "one shannon below the reserve",
            "9899999999",
            "fundedShannons 9899999999 is below the 9900000000 the device's reserve takes over that close script",
        ],
        ["nothing", "0", "fundedShannons 0 is below the 9900000000 the device's reserve takes over that close script"],
        [
            "u64's maximum",
            "18446744073709551615",
            "fundedShannons must be below 18446744073709551615, the most a CKB channel's capacity holds",
        ],
        ["above u64", "18446744073709551616", "fundedShannons must be below 18446744073709551615, the most a CKB channel's capacity holds"],
    ])("rejects %s as out of range", (_, funded, message) => {
        expect(() => assertChannelOpening(funded, CLOSE_SCRIPT)).toThrow(RangeError);
        expect(() => assertChannelOpening(funded, CLOSE_SCRIPT)).toThrow(message);
    });

    it("rejects a funded amount in hex as malformed", () => {
        expect(() => assertChannelOpening("0x1", CLOSE_SCRIPT)).toThrow(
            new TypeError("fundedShannons must be an amount in decimal shannons"),
        );
        expect(() => assertChannelOpening("0x1", CLOSE_SCRIPT)).not.toThrow(RangeError);
    });

    it("reads the reserve over the close script it is given", () => {
        const longScript = { ...CLOSE_SCRIPT, args: new Uint8Array(58) };
        expect(() => assertChannelOpening("9900000000", longScript)).toThrow(
            new RangeError("fundedShannons 9900000000 is below the 10000000000 the device's reserve takes over that close script"),
        );
        expect(() => assertChannelOpening("10000000000", longScript)).not.toThrow();
    });

    it.each([
        ["no object", null as never, "localCloseScript must be an object"],
        ["a short code hash", { ...CLOSE_SCRIPT, codeHash: new Uint8Array(31) }, "localCloseScript.codeHash must be 32 bytes, got 31"],
        [
            "an unknown hash type",
            { ...CLOSE_SCRIPT, hashType: "data3" as never },
            "localCloseScript.hashType must be one of data, type, data1, data2",
        ],
        ["args that are not bytes", { ...CLOSE_SCRIPT, args: "00" as never }, "localCloseScript.args must be a Uint8Array"],
    ])("rejects a close script with %s, naming the field", (_, script, message) => {
        expect(() => assertChannelOpening("9900000000", script)).toThrow(new TypeError(message));
    });
});

describe("openingChannelPins", () => {
    it("fixes the funded amount, the close script as its molecule bytes, the reserve fiber sizes over it, and the CKB asset", () => {
        const localCloseScript = toShutdownTxInput(caseOf(digest.shutdown_cases, "ckb"), digest.remote).localCloseScript;
        expect(openingChannelPins("71900000000", localCloseScript)).toEqual<ChannelPins>({
            fundedShannons: "71900000000",
            localCloseScript: LOCAL_CLOSE_SCRIPT_PIN,
            localReservedCkbShannons: "9900000000",
            udtTypeScript: null,
        });
    });

    it.each(digest.reserve_cases.map((kase) => [kase.name, kase] as const))("reserves what fiber does over a script with %s", (_, kase) => {
        expect(openingChannelPins(kase.reserved, toScript(kase.shutdown_script)).localReservedCkbShannons).toBe(kase.reserved);
    });

    it("refuses what the opening assertion refuses, before building anything", () => {
        expect(() => openingChannelPins("9899999999", CLOSE_SCRIPT)).toThrow(RangeError);
        expect(() => openingChannelPins("9900000000", { ...CLOSE_SCRIPT, codeHash: new Uint8Array(31) })).toThrow(
            new TypeError("localCloseScript.codeHash must be 32 bytes, got 31"),
        );
    });
});
